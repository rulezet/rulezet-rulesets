rule TTP_XOR_WriteProcessMemory_d664 {
  strings:
    $key_d664 = { 81 16 [2] b3 34 [2] b5 01 [2] 9b 01 [2] a4 1d }

  condition:
    any of them
}