rule TTP_XOR_WriteProcessMemory_6be2 {
  strings:
    $key_6be2 = { 3c 90 [2] 0e b2 [2] 08 87 [2] 26 87 [2] 19 9b }

  condition:
    any of them
}