rule TTP_XOR_WriteProcessMemory_7431 {
  strings:
    $key_7431 = { 23 43 [2] 11 61 [2] 17 54 [2] 39 54 [2] 06 48 }

  condition:
    any of them
}