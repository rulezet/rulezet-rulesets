rule TTP_XOR_WriteProcessMemory_c6e4 {
  strings:
    $key_c6e4 = { 91 96 [2] a3 b4 [2] a5 81 [2] 8b 81 [2] b4 9d }

  condition:
    any of them
}