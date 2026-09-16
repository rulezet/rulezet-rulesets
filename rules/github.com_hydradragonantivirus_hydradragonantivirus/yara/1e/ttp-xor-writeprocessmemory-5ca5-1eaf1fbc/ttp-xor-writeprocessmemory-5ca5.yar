rule TTP_XOR_WriteProcessMemory_5ca5 {
  strings:
    $key_5ca5 = { 0b d7 [2] 39 f5 [2] 3f c0 [2] 11 c0 [2] 2e dc }

  condition:
    any of them
}