rule TTP_XOR_WriteProcessMemory_64cd {
  strings:
    $key_64cd = { 33 bf [2] 01 9d [2] 07 a8 [2] 29 a8 [2] 16 b4 }

  condition:
    any of them
}