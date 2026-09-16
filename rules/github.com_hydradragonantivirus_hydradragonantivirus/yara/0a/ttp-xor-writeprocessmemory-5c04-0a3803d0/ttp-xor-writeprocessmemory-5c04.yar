rule TTP_XOR_WriteProcessMemory_5c04 {
  strings:
    $key_5c04 = { 0b 76 [2] 39 54 [2] 3f 61 [2] 11 61 [2] 2e 7d }

  condition:
    any of them
}