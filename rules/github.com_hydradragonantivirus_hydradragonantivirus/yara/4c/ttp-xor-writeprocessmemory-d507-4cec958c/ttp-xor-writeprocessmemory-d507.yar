rule TTP_XOR_WriteProcessMemory_d507 {
  strings:
    $key_d507 = { 82 75 [2] b0 57 [2] b6 62 [2] 98 62 [2] a7 7e }

  condition:
    any of them
}