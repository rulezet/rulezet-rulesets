rule TTP_XOR_WriteProcessMemory_e931 {
  strings:
    $key_e931 = { be 43 [2] 8c 61 [2] 8a 54 [2] a4 54 [2] 9b 48 }

  condition:
    any of them
}