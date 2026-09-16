rule TTP_XOR_WriteProcessMemory_d453 {
  strings:
    $key_d453 = { 83 21 [2] b1 03 [2] b7 36 [2] 99 36 [2] a6 2a }

  condition:
    any of them
}