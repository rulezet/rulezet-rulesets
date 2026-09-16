rule TTP_XOR_WriteProcessMemory_7641 {
  strings:
    $key_7641 = { 21 33 [2] 13 11 [2] 15 24 [2] 3b 24 [2] 04 38 }

  condition:
    any of them
}