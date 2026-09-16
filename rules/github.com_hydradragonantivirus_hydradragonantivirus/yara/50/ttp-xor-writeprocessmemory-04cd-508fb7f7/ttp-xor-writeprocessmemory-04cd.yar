rule TTP_XOR_WriteProcessMemory_04cd {
  strings:
    $key_04cd = { 53 bf [2] 61 9d [2] 67 a8 [2] 49 a8 [2] 76 b4 }

  condition:
    any of them
}