rule TTP_XOR_WriteProcessMemory_2652 {
  strings:
    $key_2652 = { 71 20 [2] 43 02 [2] 45 37 [2] 6b 37 [2] 54 2b }

  condition:
    any of them
}