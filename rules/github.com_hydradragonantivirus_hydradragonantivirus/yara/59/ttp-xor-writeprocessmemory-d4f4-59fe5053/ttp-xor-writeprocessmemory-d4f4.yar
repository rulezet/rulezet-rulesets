rule TTP_XOR_WriteProcessMemory_d4f4 {
  strings:
    $key_d4f4 = { 83 86 [2] b1 a4 [2] b7 91 [2] 99 91 [2] a6 8d }

  condition:
    any of them
}