rule TTP_XOR_WriteProcessMemory_32cd {
  strings:
    $key_32cd = { 65 bf [2] 57 9d [2] 51 a8 [2] 7f a8 [2] 40 b4 }

  condition:
    any of them
}