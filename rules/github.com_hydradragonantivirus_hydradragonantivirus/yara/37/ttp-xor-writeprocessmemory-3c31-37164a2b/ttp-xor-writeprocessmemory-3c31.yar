rule TTP_XOR_WriteProcessMemory_3c31 {
  strings:
    $key_3c31 = { 6b 43 [2] 59 61 [2] 5f 54 [2] 71 54 [2] 4e 48 }

  condition:
    any of them
}