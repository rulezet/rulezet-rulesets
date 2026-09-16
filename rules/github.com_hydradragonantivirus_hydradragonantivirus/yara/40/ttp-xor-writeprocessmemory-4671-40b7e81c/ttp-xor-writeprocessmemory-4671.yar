rule TTP_XOR_WriteProcessMemory_4671 {
  strings:
    $key_4671 = { 11 03 [2] 23 21 [2] 25 14 [2] 0b 14 [2] 34 08 }

  condition:
    any of them
}