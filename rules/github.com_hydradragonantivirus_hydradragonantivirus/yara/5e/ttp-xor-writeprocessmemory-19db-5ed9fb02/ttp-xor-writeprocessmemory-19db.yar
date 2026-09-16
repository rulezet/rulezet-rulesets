rule TTP_XOR_WriteProcessMemory_19db {
  strings:
    $key_19db = { 4e a9 [2] 7c 8b [2] 7a be [2] 54 be [2] 6b a2 }

  condition:
    any of them
}