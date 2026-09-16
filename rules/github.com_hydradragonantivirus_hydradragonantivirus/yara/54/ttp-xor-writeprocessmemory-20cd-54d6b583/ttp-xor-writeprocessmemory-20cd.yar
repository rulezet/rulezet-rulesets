rule TTP_XOR_WriteProcessMemory_20cd {
  strings:
    $key_20cd = { 77 bf [2] 45 9d [2] 43 a8 [2] 6d a8 [2] 52 b4 }

  condition:
    any of them
}