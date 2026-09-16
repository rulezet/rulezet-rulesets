rule TTP_XOR_WriteProcessMemory_6671 {
  strings:
    $key_6671 = { 31 03 [2] 03 21 [2] 05 14 [2] 2b 14 [2] 14 08 }

  condition:
    any of them
}