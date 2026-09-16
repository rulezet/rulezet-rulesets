rule TTP_XOR_WriteProcessMemory_03db {
  strings:
    $key_03db = { 54 a9 [2] 66 8b [2] 60 be [2] 4e be [2] 71 a2 }

  condition:
    any of them
}