rule TTP_XOR_WriteProcessMemory_d631 {
  strings:
    $key_d631 = { 81 43 [2] b3 61 [2] b5 54 [2] 9b 54 [2] a4 48 }

  condition:
    any of them
}