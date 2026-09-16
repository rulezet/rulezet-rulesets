rule TTP_XOR_WriteProcessMemory_60cd {
  strings:
    $key_60cd = { 37 bf [2] 05 9d [2] 03 a8 [2] 2d a8 [2] 12 b4 }

  condition:
    any of them
}