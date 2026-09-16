rule TTP_XOR_WriteProcessMemory_d785 {
  strings:
    $key_d785 = { 80 f7 [2] b2 d5 [2] b4 e0 [2] 9a e0 [2] a5 fc }

  condition:
    any of them
}