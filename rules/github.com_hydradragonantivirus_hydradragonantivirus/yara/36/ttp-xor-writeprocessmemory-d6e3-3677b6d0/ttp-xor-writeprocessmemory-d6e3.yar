rule TTP_XOR_WriteProcessMemory_d6e3 {
  strings:
    $key_d6e3 = { 81 91 [2] b3 b3 [2] b5 86 [2] 9b 86 [2] a4 9a }

  condition:
    any of them
}