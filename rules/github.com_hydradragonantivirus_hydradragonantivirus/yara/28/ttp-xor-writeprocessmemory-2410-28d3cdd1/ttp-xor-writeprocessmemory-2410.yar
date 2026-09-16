rule TTP_XOR_WriteProcessMemory_2410 {
  strings:
    $key_2410 = { 73 62 [2] 41 40 [2] 47 75 [2] 69 75 [2] 56 69 }

  condition:
    any of them
}