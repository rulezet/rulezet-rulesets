rule TTP_XOR_WriteProcessMemory_d653 {
  strings:
    $key_d653 = { 81 21 [2] b3 03 [2] b5 36 [2] 9b 36 [2] a4 2a }

  condition:
    any of them
}