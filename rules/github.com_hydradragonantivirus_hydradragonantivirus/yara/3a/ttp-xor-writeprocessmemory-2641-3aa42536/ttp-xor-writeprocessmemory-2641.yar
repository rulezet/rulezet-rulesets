rule TTP_XOR_WriteProcessMemory_2641 {
  strings:
    $key_2641 = { 71 33 [2] 43 11 [2] 45 24 [2] 6b 24 [2] 54 38 }

  condition:
    any of them
}