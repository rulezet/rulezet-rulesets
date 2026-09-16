rule TTP_XOR_WriteProcessMemory_52cd {
  strings:
    $key_52cd = { 05 bf [2] 37 9d [2] 31 a8 [2] 1f a8 [2] 20 b4 }

  condition:
    any of them
}