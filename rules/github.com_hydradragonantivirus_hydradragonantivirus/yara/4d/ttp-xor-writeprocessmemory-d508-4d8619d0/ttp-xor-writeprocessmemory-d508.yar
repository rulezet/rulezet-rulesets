rule TTP_XOR_WriteProcessMemory_d508 {
  strings:
    $key_d508 = { 82 7a [2] b0 58 [2] b6 6d [2] 98 6d [2] a7 71 }

  condition:
    any of them
}