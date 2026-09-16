rule TTP_XOR_WriteProcessMemory_39db {
  strings:
    $key_39db = { 6e a9 [2] 5c 8b [2] 5a be [2] 74 be [2] 4b a2 }

  condition:
    any of them
}