rule TTP_XOR_WriteProcessMemory_d404 {
  strings:
    $key_d404 = { 83 76 [2] b1 54 [2] b7 61 [2] 99 61 [2] a6 7d }

  condition:
    any of them
}