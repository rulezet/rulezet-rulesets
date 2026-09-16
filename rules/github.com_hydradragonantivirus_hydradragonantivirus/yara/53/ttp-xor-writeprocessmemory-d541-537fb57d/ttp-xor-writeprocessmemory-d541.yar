rule TTP_XOR_WriteProcessMemory_d541 {
  strings:
    $key_d541 = { 82 33 [2] b0 11 [2] b6 24 [2] 98 24 [2] a7 38 }

  condition:
    any of them
}