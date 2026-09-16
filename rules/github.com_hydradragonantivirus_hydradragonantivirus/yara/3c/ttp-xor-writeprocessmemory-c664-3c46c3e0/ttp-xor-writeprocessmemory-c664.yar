rule TTP_XOR_WriteProcessMemory_c664 {
  strings:
    $key_c664 = { 91 16 [2] a3 34 [2] a5 01 [2] 8b 01 [2] b4 1d }

  condition:
    any of them
}