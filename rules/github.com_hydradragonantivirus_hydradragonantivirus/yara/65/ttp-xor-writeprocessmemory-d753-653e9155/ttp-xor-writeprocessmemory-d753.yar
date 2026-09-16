rule TTP_XOR_WriteProcessMemory_d753 {
  strings:
    $key_d753 = { 80 21 [2] b2 03 [2] b4 36 [2] 9a 36 [2] a5 2a }

  condition:
    any of them
}