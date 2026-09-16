rule TTP_XOR_WriteProcessMemory_3141 {
  strings:
    $key_3141 = { 66 33 [2] 54 11 [2] 52 24 [2] 7c 24 [2] 43 38 }

  condition:
    any of them
}