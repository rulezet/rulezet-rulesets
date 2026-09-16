rule TTP_XOR_WriteProcessMemory_d551 {
  strings:
    $key_d551 = { 82 23 [2] b0 01 [2] b6 34 [2] 98 34 [2] a7 28 }

  condition:
    any of them
}