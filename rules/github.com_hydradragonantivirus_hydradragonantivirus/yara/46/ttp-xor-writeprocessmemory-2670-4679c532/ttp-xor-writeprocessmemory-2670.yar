rule TTP_XOR_WriteProcessMemory_2670 {
  strings:
    $key_2670 = { 71 02 [2] 43 20 [2] 45 15 [2] 6b 15 [2] 54 09 }

  condition:
    any of them
}