rule TTP_XOR_WriteProcessMemory_1f31 {
  strings:
    $key_1f31 = { 48 43 [2] 7a 61 [2] 7c 54 [2] 52 54 [2] 6d 48 }

  condition:
    any of them
}