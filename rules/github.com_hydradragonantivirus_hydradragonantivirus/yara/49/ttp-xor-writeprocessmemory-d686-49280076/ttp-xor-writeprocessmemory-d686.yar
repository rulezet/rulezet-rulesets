rule TTP_XOR_WriteProcessMemory_d686 {
  strings:
    $key_d686 = { 81 f4 [2] b3 d6 [2] b5 e3 [2] 9b e3 [2] a4 ff }

  condition:
    any of them
}