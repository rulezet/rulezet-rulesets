rule TTP_XOR_WriteProcessMemory_d177 {
  strings:
    $key_d177 = { 86 05 [2] b4 27 [2] b2 12 [2] 9c 12 [2] a3 0e }

  condition:
    any of them
}