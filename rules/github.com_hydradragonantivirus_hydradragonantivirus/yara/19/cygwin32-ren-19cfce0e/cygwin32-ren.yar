import "pe"
rule Cygwin32_ren: Packer PEiD {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 55 89 E5 83 EC 04 83 3D }

  condition:
    $a0 at pe.entry_point
}