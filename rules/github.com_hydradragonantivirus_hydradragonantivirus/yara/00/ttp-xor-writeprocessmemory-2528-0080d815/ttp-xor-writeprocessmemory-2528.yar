rule TTP_XOR_WriteProcessMemory_2528 {
  strings:
    $key_2528 = { 72 5a [2] 40 78 [2] 46 4d [2] 68 4d [2] 57 51 }

  condition:
    any of them
}