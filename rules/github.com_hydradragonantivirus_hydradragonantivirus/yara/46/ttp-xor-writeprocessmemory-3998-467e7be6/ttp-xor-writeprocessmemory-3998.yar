rule TTP_XOR_WriteProcessMemory_3998 {
  strings:
    $key_3998 = { 6e ea [2] 5c c8 [2] 5a fd [2] 74 fd [2] 4b e1 }

  condition:
    any of them
}