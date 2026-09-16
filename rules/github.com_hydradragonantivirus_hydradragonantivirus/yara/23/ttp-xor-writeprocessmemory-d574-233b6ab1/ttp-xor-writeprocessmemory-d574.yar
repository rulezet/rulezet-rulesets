rule TTP_XOR_WriteProcessMemory_d574 {
  strings:
    $key_d574 = { 82 06 [2] b0 24 [2] b6 11 [2] 98 11 [2] a7 0d }

  condition:
    any of them
}