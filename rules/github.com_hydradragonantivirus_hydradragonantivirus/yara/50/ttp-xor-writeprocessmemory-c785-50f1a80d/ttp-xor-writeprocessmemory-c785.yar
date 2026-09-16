rule TTP_XOR_WriteProcessMemory_c785 {
  strings:
    $key_c785 = { 90 f7 [2] a2 d5 [2] a4 e0 [2] 8a e0 [2] b5 fc }

  condition:
    any of them
}