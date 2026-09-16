rule TTP_XOR_WriteProcessMemory_d518 {
  strings:
    $key_d518 = { 82 6a [2] b0 48 [2] b6 7d [2] 98 7d [2] a7 61 }

  condition:
    any of them
}