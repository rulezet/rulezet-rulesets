rule TTP_XOR_WriteProcessMemory_7998 {
  strings:
    $key_7998 = { 2e ea [2] 1c c8 [2] 1a fd [2] 34 fd [2] 0b e1 }

  condition:
    any of them
}