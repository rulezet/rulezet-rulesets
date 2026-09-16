rule TTP_XOR_WriteProcessMemory_2b42 {
  strings:
    $key_2b42 = { 7c 30 [2] 4e 12 [2] 48 27 [2] 66 27 [2] 59 3b }

  condition:
    any of them
}