rule TTP_XOR_WriteProcessMemory_d621 {
  strings:
    $key_d621 = { 81 53 [2] b3 71 [2] b5 44 [2] 9b 44 [2] a4 58 }

  condition:
    any of them
}