rule TTP_XOR_WriteProcessMemory_d534 {
  strings:
    $key_d534 = { 82 46 [2] b0 64 [2] b6 51 [2] 98 51 [2] a7 4d }

  condition:
    any of them
}