rule TTP_XOR_WriteProcessMemory_c666 {
  strings:
    $key_c666 = { 91 14 [2] a3 36 [2] a5 03 [2] 8b 03 [2] b4 1f }

  condition:
    any of them
}