rule TTP_XOR_WriteProcessMemory_53cd {
  strings:
    $key_53cd = { 04 bf [2] 36 9d [2] 30 a8 [2] 1e a8 [2] 21 b4 }

  condition:
    any of them
}