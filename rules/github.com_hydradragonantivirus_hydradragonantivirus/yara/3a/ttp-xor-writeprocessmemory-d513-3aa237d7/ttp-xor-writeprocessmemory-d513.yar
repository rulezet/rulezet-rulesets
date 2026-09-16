rule TTP_XOR_WriteProcessMemory_d513 {
  strings:
    $key_d513 = { 82 61 [2] b0 43 [2] b6 76 [2] 98 76 [2] a7 6a }

  condition:
    any of them
}