rule PEiD_00987_Lotus_Word_Pro_document_file_ {
  meta:
    description = "[Lotus Word Pro document file]"
    ep_only     = "false"

  strings:
    $a = { 57 6F 72 64 50 72 6F ?? ?? ?? ?? ?? ?? ?? ?? ?? 4C 57 50 37 }

  condition:
    $a
}