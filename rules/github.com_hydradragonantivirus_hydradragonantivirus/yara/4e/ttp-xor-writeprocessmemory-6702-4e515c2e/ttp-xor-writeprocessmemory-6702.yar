rule TTP_XOR_WriteProcessMemory_6702 {
  strings:
    $key_6702 = { 30 70 [2] 02 52 [2] 04 67 [2] 2a 67 [2] 15 7b }

  condition:
    any of them
}