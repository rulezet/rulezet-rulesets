rule TTP_XOR_WriteProcessMemory_54cd {
  strings:
    $key_54cd = { 03 bf [2] 31 9d [2] 37 a8 [2] 19 a8 [2] 26 b4 }

  condition:
    any of them
}