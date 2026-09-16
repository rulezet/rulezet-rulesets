rule TTP_XOR_WriteProcessMemory_7904 {
  strings:
    $key_7904 = { 2e 76 [2] 1c 54 [2] 1a 61 [2] 34 61 [2] 0b 7d }

  condition:
    any of them
}