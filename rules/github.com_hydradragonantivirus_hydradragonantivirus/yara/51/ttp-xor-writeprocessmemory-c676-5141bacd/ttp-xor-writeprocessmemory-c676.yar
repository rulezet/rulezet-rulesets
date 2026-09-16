rule TTP_XOR_WriteProcessMemory_c676 {
  strings:
    $key_c676 = { 91 04 [2] a3 26 [2] a5 13 [2] 8b 13 [2] b4 0f }

  condition:
    any of them
}