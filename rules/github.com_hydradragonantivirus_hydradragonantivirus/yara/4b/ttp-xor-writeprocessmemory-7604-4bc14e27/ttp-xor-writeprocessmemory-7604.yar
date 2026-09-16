rule TTP_XOR_WriteProcessMemory_7604 {
  strings:
    $key_7604 = { 21 76 [2] 13 54 [2] 15 61 [2] 3b 61 [2] 04 7d }

  condition:
    any of them
}