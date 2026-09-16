rule TTP_XOR_WriteProcessMemory_4531 {
  strings:
    $key_4531 = { 12 43 [2] 20 61 [2] 26 54 [2] 08 54 [2] 37 48 }

  condition:
    any of them
}