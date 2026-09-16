rule TTP_XOR_WriteProcessMemory_38a5 {
  strings:
    $key_38a5 = { 6f d7 [2] 5d f5 [2] 5b c0 [2] 75 c0 [2] 4a dc }

  condition:
    any of them
}