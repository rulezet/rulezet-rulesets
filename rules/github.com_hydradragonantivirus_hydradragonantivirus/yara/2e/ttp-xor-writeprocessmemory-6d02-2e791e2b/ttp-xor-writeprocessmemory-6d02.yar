rule TTP_XOR_WriteProcessMemory_6d02 {
  strings:
    $key_6d02 = { 3a 70 [2] 08 52 [2] 0e 67 [2] 20 67 [2] 1f 7b }

  condition:
    any of them
}