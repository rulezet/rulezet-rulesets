rule TTP_XOR_WriteProcessMemory_2210 {
  strings:
    $key_2210 = { 75 62 [2] 47 40 [2] 41 75 [2] 6f 75 [2] 50 69 }

  condition:
    any of them
}