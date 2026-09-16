rule TTP_XOR_WriteProcessMemory_7163 {
  strings:
    $key_7163 = { 26 11 [2] 14 33 [2] 12 06 [2] 3c 06 [2] 03 1a }

  condition:
    any of them
}