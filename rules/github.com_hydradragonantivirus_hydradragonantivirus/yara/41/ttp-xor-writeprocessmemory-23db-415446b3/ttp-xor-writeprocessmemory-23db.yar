rule TTP_XOR_WriteProcessMemory_23db {
  strings:
    $key_23db = { 74 a9 [2] 46 8b [2] 40 be [2] 6e be [2] 51 a2 }

  condition:
    any of them
}