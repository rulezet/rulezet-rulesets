rule TTP_XOR_WriteProcessMemory_25cd {
  strings:
    $key_25cd = { 72 bf [2] 40 9d [2] 46 a8 [2] 68 a8 [2] 57 b4 }

  condition:
    any of them
}