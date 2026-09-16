rule TTP_XOR_WriteProcessMemory_66e4 {
  strings:
    $key_66e4 = { 31 96 [2] 03 b4 [2] 05 81 [2] 2b 81 [2] 14 9d }

  condition:
    any of them
}