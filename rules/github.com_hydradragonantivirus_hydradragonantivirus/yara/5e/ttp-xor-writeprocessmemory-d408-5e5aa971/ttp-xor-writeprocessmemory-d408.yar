rule TTP_XOR_WriteProcessMemory_d408 {
  strings:
    $key_d408 = { 83 7a [2] b1 58 [2] b7 6d [2] 99 6d [2] a6 71 }

  condition:
    any of them
}