rule TTP_XOR_WriteProcessMemory_d521 {
  strings:
    $key_d521 = { 82 53 [2] b0 71 [2] b6 44 [2] 98 44 [2] a7 58 }

  condition:
    any of them
}