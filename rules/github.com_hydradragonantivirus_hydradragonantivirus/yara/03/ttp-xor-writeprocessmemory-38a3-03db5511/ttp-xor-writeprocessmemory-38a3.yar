rule TTP_XOR_WriteProcessMemory_38a3 {
  strings:
    $key_38a3 = { 6f d1 [2] 5d f3 [2] 5b c6 [2] 75 c6 [2] 4a da }

  condition:
    any of them
}