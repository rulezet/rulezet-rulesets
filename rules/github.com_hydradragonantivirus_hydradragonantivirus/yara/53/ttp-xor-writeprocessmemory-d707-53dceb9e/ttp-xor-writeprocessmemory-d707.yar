rule TTP_XOR_WriteProcessMemory_d707 {
  strings:
    $key_d707 = { 80 75 [2] b2 57 [2] b4 62 [2] 9a 62 [2] a5 7e }

  condition:
    any of them
}