rule TTP_XOR_WriteProcessMemory_d040 {
  strings:
    $key_d040 = { 87 32 [2] b5 10 [2] b3 25 [2] 9d 25 [2] a2 39 }

  condition:
    any of them
}