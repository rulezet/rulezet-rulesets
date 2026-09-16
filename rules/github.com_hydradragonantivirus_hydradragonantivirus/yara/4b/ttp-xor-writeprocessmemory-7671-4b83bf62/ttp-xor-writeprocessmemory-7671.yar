rule TTP_XOR_WriteProcessMemory_7671 {
  strings:
    $key_7671 = { 21 03 [2] 13 21 [2] 15 14 [2] 3b 14 [2] 04 08 }

  condition:
    any of them
}