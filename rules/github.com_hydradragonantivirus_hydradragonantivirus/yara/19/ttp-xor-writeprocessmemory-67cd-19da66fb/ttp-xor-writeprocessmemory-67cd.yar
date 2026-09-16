rule TTP_XOR_WriteProcessMemory_67cd {
  strings:
    $key_67cd = { 30 bf [2] 02 9d [2] 04 a8 [2] 2a a8 [2] 15 b4 }

  condition:
    any of them
}