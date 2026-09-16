rule TTP_XOR_WriteProcessMemory_c786 {
  strings:
    $key_c786 = { 90 f4 [2] a2 d6 [2] a4 e3 [2] 8a e3 [2] b5 ff }

  condition:
    any of them
}