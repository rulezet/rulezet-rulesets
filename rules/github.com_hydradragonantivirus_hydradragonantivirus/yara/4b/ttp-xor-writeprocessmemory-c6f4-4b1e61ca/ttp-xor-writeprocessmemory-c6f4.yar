rule TTP_XOR_WriteProcessMemory_c6f4 {
  strings:
    $key_c6f4 = { 91 86 [2] a3 a4 [2] a5 91 [2] 8b 91 [2] b4 8d }

  condition:
    any of them
}