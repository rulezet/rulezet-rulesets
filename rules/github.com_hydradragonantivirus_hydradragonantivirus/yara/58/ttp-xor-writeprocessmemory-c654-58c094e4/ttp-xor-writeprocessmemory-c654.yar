rule TTP_XOR_WriteProcessMemory_c654 {
  strings:
    $key_c654 = { 91 26 [2] a3 04 [2] a5 31 [2] 8b 31 [2] b4 2d }

  condition:
    any of them
}