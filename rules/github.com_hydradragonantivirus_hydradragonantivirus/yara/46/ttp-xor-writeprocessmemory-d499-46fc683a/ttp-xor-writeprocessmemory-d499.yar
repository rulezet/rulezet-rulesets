rule TTP_XOR_WriteProcessMemory_d499 {
  strings:
    $key_d499 = { 83 eb [2] b1 c9 [2] b7 fc [2] 99 fc [2] a6 e0 }

  condition:
    any of them
}