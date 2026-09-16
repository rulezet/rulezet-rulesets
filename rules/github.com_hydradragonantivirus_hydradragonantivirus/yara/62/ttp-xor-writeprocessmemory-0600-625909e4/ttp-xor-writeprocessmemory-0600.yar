rule TTP_XOR_WriteProcessMemory_0600 {
  strings:
    $key_0600 = { 51 72 [2] 63 50 [2] 65 65 [2] 4b 65 [2] 74 79 }

  condition:
    any of them
}