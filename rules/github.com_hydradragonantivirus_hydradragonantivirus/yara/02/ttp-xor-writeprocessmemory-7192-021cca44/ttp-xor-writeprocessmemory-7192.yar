rule TTP_XOR_WriteProcessMemory_7192 {
  strings:
    $key_7192 = { 26 e0 [2] 14 c2 [2] 12 f7 [2] 3c f7 [2] 03 eb }

  condition:
    any of them
}