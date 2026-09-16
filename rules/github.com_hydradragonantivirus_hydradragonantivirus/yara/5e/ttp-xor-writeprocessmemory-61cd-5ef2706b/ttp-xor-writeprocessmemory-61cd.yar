rule TTP_XOR_WriteProcessMemory_61cd {
  strings:
    $key_61cd = { 36 bf [2] 04 9d [2] 02 a8 [2] 2c a8 [2] 13 b4 }

  condition:
    any of them
}