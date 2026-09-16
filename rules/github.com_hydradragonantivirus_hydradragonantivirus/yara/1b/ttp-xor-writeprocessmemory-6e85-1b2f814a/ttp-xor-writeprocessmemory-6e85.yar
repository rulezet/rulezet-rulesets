rule TTP_XOR_WriteProcessMemory_6e85 {
  strings:
    $key_6e85 = { 39 f7 [2] 0b d5 [2] 0d e0 [2] 23 e0 [2] 1c fc }

  condition:
    any of them
}