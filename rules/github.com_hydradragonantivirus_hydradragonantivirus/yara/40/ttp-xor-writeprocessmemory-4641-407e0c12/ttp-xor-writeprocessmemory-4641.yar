rule TTP_XOR_WriteProcessMemory_4641 {
  strings:
    $key_4641 = { 11 33 [2] 23 11 [2] 25 24 [2] 0b 24 [2] 34 38 }

  condition:
    any of them
}