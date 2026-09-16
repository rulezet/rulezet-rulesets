rule TTP_XOR_WriteProcessMemory_47cd {
  strings:
    $key_47cd = { 10 bf [2] 22 9d [2] 24 a8 [2] 0a a8 [2] 35 b4 }

  condition:
    any of them
}