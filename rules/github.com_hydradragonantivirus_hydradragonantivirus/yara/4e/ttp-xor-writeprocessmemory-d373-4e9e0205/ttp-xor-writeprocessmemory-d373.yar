rule TTP_XOR_WriteProcessMemory_d373 {
  strings:
    $key_d373 = { 84 01 [2] b6 23 [2] b0 16 [2] 9e 16 [2] a1 0a }

  condition:
    any of them
}