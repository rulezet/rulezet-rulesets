rule TTP_XOR_WriteProcessMemory_c164 {
  strings:
    $key_c164 = { 96 16 [2] a4 34 [2] a2 01 [2] 8c 01 [2] b3 1d }

  condition:
    any of them
}