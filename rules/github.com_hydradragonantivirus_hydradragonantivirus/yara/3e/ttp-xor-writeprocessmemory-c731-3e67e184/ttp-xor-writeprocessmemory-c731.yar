rule TTP_XOR_WriteProcessMemory_c731 {
  strings:
    $key_c731 = { 90 43 [2] a2 61 [2] a4 54 [2] 8a 54 [2] b5 48 }

  condition:
    any of them
}