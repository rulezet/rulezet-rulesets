rule TTP_XOR_WriteProcessMemory_3f02 {
  strings:
    $key_3f02 = { 68 70 [2] 5a 52 [2] 5c 67 [2] 72 67 [2] 4d 7b }

  condition:
    any of them
}