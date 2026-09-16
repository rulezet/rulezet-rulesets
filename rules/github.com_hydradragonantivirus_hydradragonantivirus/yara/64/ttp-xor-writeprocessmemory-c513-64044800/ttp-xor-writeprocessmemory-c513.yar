rule TTP_XOR_WriteProcessMemory_c513 {
  strings:
    $key_c513 = { 92 61 [2] a0 43 [2] a6 76 [2] 88 76 [2] b7 6a }

  condition:
    any of them
}