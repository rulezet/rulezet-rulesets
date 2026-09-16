rule TTP_XOR_WriteProcessMemory_6741 {
  strings:
    $key_6741 = { 30 33 [2] 02 11 [2] 04 24 [2] 2a 24 [2] 15 38 }

  condition:
    any of them
}