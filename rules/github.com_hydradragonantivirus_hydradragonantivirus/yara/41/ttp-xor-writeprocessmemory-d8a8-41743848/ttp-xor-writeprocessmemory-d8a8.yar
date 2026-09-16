rule TTP_XOR_WriteProcessMemory_d8a8 {
  strings:
    $key_d8a8 = { 8f da [2] bd f8 [2] bb cd [2] 95 cd [2] aa d1 }

  condition:
    any of them
}