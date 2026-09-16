rule TTP_XOR_WriteProcessMemory_2671 {
  strings:
    $key_2671 = { 71 03 [2] 43 21 [2] 45 14 [2] 6b 14 [2] 54 08 }

  condition:
    any of them
}