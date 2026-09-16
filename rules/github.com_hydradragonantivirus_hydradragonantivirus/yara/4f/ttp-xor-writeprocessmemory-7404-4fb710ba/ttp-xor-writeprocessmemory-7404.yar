rule TTP_XOR_WriteProcessMemory_7404 {
  strings:
    $key_7404 = { 23 76 [2] 11 54 [2] 17 61 [2] 39 61 [2] 06 7d }

  condition:
    any of them
}