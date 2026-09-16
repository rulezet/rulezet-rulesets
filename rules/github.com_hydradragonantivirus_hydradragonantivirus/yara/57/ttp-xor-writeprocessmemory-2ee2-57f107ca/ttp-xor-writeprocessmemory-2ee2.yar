rule TTP_XOR_WriteProcessMemory_2ee2 {
  strings:
    $key_2ee2 = { 79 90 [2] 4b b2 [2] 4d 87 [2] 63 87 [2] 5c 9b }

  condition:
    any of them
}