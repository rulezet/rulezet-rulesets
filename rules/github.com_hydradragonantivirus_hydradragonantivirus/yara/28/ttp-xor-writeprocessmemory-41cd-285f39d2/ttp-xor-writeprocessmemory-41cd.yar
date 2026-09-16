rule TTP_XOR_WriteProcessMemory_41cd {
  strings:
    $key_41cd = { 16 bf [2] 24 9d [2] 22 a8 [2] 0c a8 [2] 33 b4 }

  condition:
    any of them
}