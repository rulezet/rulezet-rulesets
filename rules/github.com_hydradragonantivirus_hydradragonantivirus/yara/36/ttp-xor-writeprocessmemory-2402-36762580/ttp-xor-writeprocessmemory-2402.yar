rule TTP_XOR_WriteProcessMemory_2402 {
  strings:
    $key_2402 = { 73 70 [2] 41 52 [2] 47 67 [2] 69 67 [2] 56 7b }

  condition:
    any of them
}