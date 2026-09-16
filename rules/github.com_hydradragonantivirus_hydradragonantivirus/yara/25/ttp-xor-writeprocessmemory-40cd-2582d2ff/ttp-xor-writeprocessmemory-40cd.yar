rule TTP_XOR_WriteProcessMemory_40cd {
  strings:
    $key_40cd = { 17 bf [2] 25 9d [2] 23 a8 [2] 0d a8 [2] 32 b4 }

  condition:
    any of them
}