rule TTP_XOR_WriteProcessMemory_d113 {
  strings:
    $key_d113 = { 86 61 [2] b4 43 [2] b2 76 [2] 9c 76 [2] a3 6a }

  condition:
    any of them
}