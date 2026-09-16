rule TTP_XOR_WriteProcessMemory_14db {
  strings:
    $key_14db = { 43 a9 [2] 71 8b [2] 77 be [2] 59 be [2] 66 a2 }

  condition:
    any of them
}