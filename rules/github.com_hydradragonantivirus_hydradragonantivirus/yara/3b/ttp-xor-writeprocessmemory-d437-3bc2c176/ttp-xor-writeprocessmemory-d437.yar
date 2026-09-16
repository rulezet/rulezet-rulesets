rule TTP_XOR_WriteProcessMemory_d437 {
  strings:
    $key_d437 = { 83 45 [2] b1 67 [2] b7 52 [2] 99 52 [2] a6 4e }

  condition:
    any of them
}