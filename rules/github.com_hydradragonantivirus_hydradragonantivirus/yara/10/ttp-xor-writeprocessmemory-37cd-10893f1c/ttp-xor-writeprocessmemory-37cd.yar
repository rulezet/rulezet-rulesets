rule TTP_XOR_WriteProcessMemory_37cd {
  strings:
    $key_37cd = { 60 bf [2] 52 9d [2] 54 a8 [2] 7a a8 [2] 45 b4 }

  condition:
    any of them
}