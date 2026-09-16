rule TTP_XOR_WriteProcessMemory_2600 {
  strings:
    $key_2600 = { 71 72 [2] 43 50 [2] 45 65 [2] 6b 65 [2] 54 79 }

  condition:
    any of them
}