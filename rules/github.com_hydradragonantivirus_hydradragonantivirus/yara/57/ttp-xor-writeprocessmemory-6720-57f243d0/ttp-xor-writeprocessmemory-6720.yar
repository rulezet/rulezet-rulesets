rule TTP_XOR_WriteProcessMemory_6720 {
  strings:
    $key_6720 = { 30 52 [2] 02 70 [2] 04 45 [2] 2a 45 [2] 15 59 }

  condition:
    any of them
}