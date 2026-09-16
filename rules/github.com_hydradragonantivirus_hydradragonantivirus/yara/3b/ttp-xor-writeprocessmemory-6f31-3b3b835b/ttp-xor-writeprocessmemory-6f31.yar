rule TTP_XOR_WriteProcessMemory_6f31 {
  strings:
    $key_6f31 = { 38 43 [2] 0a 61 [2] 0c 54 [2] 22 54 [2] 1d 48 }

  condition:
    any of them
}