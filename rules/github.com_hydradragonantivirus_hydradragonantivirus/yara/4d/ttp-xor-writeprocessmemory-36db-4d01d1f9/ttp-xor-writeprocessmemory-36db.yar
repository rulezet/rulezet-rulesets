rule TTP_XOR_WriteProcessMemory_36db {
  strings:
    $key_36db = { 61 a9 [2] 53 8b [2] 55 be [2] 7b be [2] 44 a2 }

  condition:
    any of them
}