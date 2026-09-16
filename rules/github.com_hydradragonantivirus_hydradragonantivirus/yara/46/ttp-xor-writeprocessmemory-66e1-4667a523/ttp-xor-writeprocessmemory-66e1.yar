rule TTP_XOR_WriteProcessMemory_66e1 {
  strings:
    $key_66e1 = { 31 93 [2] 03 b1 [2] 05 84 [2] 2b 84 [2] 14 98 }

  condition:
    any of them
}