rule TTP_XOR_WriteProcessMemory_23f2 {
  strings:
    $key_23f2 = { 74 80 [2] 46 a2 [2] 40 97 [2] 6e 97 [2] 51 8b }

  condition:
    any of them
}