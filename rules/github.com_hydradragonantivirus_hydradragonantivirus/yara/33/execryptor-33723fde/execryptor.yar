import "pe"
rule EXECryptor: SoftComplete {
  meta:
    author      = "_pusher_"
    date        = "2016-07"
    description = "EXECryptor"

  strings:
    $c0 = "kern" nocase
    $c1 = "GetM" nocase
    $c2 = "Load" nocase
    $c3 = "Exit" nocase

  condition:
    (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset + 0x8a < filesize)
    and $c0 at (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset + 0x3c)
    and $c1 at (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset + 0x4e)
    and $c2 at (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset + 0x62)
    and $c3 at (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset + 0x86)
}