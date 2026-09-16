rule TTP_XOR_WriteProcessMemory_3f31 {
  strings:
    $key_3f31 = { 68 43 [2] 5a 61 [2] 5c 54 [2] 72 54 [2] 4d 48 }

  condition:
    any of them
}