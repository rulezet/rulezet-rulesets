rule TTP_XOR_WriteProcessMemory_78f2 {
  strings:
    $key_78f2 = { 2f 80 [2] 1d a2 [2] 1b 97 [2] 35 97 [2] 0a 8b }

  condition:
    any of them
}