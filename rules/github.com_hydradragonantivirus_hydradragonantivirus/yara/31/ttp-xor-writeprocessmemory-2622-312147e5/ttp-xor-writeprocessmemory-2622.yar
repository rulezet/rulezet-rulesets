rule TTP_XOR_WriteProcessMemory_2622 {
  strings:
    $key_2622 = { 71 50 [2] 43 72 [2] 45 47 [2] 6b 47 [2] 54 5b }

  condition:
    any of them
}