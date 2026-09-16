rule TTP_XOR_WriteProcessMemory_cddb {
  strings:
    $key_cddb = { 9a a9 [2] a8 8b [2] ae be [2] 80 be [2] bf a2 }

  condition:
    any of them
}