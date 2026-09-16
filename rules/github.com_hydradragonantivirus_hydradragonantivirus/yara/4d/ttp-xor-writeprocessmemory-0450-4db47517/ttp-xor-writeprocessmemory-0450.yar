rule TTP_XOR_WriteProcessMemory_0450 {
  strings:
    $key_0450 = { 53 22 [2] 61 00 [2] 67 35 [2] 49 35 [2] 76 29 }

  condition:
    any of them
}