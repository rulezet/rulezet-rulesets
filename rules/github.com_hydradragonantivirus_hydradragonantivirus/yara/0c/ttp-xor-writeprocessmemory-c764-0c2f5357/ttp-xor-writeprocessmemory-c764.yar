rule TTP_XOR_WriteProcessMemory_c764 {
  strings:
    $key_c764 = { 90 16 [2] a2 34 [2] a4 01 [2] 8a 01 [2] b5 1d }

  condition:
    any of them
}