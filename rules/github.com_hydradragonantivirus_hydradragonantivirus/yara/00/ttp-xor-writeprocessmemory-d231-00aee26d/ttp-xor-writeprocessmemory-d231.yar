rule TTP_XOR_WriteProcessMemory_d231 {
  strings:
    $key_d231 = { 85 43 [2] b7 61 [2] b1 54 [2] 9f 54 [2] a0 48 }

  condition:
    any of them
}