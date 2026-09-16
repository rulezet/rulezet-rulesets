rule TTP_XOR_WriteProcessMemory_d531 {
  strings:
    $key_d531 = { 82 43 [2] b0 61 [2] b6 54 [2] 98 54 [2] a7 48 }

  condition:
    any of them
}