rule TTP_XOR_WriteProcessMemory_0860 {
  strings:
    $key_0860 = { 5f 12 [2] 6d 30 [2] 6b 05 [2] 45 05 [2] 7a 19 }

  condition:
    any of them
}