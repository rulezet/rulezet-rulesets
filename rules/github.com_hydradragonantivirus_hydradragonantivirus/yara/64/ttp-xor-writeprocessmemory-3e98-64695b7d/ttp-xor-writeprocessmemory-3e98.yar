rule TTP_XOR_WriteProcessMemory_3e98 {
  strings:
    $key_3e98 = { 69 ea [2] 5b c8 [2] 5d fd [2] 73 fd [2] 4c e1 }

  condition:
    any of them
}