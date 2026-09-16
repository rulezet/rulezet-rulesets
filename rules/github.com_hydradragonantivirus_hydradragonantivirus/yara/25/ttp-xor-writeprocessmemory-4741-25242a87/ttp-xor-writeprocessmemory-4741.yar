rule TTP_XOR_WriteProcessMemory_4741 {
  strings:
    $key_4741 = { 10 33 [2] 22 11 [2] 24 24 [2] 0a 24 [2] 35 38 }

  condition:
    any of them
}