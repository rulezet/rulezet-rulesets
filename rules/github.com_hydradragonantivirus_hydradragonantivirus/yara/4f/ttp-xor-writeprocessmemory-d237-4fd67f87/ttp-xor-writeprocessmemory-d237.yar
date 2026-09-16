rule TTP_XOR_WriteProcessMemory_d237 {
  strings:
    $key_d237 = { 85 45 [2] b7 67 [2] b1 52 [2] 9f 52 [2] a0 4e }

  condition:
    any of them
}