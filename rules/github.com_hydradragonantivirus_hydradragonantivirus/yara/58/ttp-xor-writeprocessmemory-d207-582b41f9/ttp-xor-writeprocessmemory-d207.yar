rule TTP_XOR_WriteProcessMemory_d207 {
  strings:
    $key_d207 = { 85 75 [2] b7 57 [2] b1 62 [2] 9f 62 [2] a0 7e }

  condition:
    any of them
}