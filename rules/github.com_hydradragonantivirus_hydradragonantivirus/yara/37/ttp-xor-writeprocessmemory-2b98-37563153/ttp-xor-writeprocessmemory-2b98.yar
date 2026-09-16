rule TTP_XOR_WriteProcessMemory_2b98 {
  strings:
    $key_2b98 = { 7c ea [2] 4e c8 [2] 48 fd [2] 66 fd [2] 59 e1 }

  condition:
    any of them
}