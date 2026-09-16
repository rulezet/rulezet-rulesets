rule TTP_XOR_WriteProcessMemory_e3db {
  strings:
    $key_e3db = { b4 a9 [2] 86 8b [2] 80 be [2] ae be [2] 91 a2 }

  condition:
    any of them
}