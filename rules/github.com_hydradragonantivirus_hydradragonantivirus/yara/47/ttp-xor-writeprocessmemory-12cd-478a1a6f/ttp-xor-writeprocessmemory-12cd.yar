rule TTP_XOR_WriteProcessMemory_12cd {
  strings:
    $key_12cd = { 45 bf [2] 77 9d [2] 71 a8 [2] 5f a8 [2] 60 b4 }

  condition:
    any of them
}