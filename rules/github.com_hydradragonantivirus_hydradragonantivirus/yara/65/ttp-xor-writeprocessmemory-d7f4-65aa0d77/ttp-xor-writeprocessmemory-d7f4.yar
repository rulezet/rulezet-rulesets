rule TTP_XOR_WriteProcessMemory_d7f4 {
  strings:
    $key_d7f4 = { 80 86 [2] b2 a4 [2] b4 91 [2] 9a 91 [2] a5 8d }

  condition:
    any of them
}