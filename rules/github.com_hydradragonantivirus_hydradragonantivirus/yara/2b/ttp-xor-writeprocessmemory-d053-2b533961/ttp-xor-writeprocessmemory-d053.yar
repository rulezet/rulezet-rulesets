rule TTP_XOR_WriteProcessMemory_d053 {
  strings:
    $key_d053 = { 87 21 [2] b5 03 [2] b3 36 [2] 9d 36 [2] a2 2a }

  condition:
    any of them
}