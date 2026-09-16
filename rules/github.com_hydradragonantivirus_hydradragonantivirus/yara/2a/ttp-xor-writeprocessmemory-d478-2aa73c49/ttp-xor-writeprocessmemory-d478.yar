rule TTP_XOR_WriteProcessMemory_d478 {
  strings:
    $key_d478 = { 83 0a [2] b1 28 [2] b7 1d [2] 99 1d [2] a6 01 }

  condition:
    any of them
}