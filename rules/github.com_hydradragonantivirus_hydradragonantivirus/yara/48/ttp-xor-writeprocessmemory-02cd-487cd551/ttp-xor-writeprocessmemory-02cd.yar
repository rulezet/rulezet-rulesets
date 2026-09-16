rule TTP_XOR_WriteProcessMemory_02cd {
  strings:
    $key_02cd = { 55 bf [2] 67 9d [2] 61 a8 [2] 4f a8 [2] 70 b4 }

  condition:
    any of them
}