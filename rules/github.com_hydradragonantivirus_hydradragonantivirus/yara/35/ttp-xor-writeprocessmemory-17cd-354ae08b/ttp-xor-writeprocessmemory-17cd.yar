rule TTP_XOR_WriteProcessMemory_17cd {
  strings:
    $key_17cd = { 40 bf [2] 72 9d [2] 74 a8 [2] 5a a8 [2] 65 b4 }

  condition:
    any of them
}