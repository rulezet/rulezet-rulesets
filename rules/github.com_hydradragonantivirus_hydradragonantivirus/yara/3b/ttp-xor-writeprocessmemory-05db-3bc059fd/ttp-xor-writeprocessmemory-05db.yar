rule TTP_XOR_WriteProcessMemory_05db {
  strings:
    $key_05db = { 52 a9 [2] 60 8b [2] 66 be [2] 48 be [2] 77 a2 }

  condition:
    any of them
}