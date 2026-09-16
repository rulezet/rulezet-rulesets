rule TTP_XOR_WriteProcessMemory_7193 {
  strings:
    $key_7193 = { 26 e1 [2] 14 c3 [2] 12 f6 [2] 3c f6 [2] 03 ea }

  condition:
    any of them
}