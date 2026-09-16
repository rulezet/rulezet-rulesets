rule TTP_XOR_WriteProcessMemory_6f04 {
  strings:
    $key_6f04 = { 38 76 [2] 0a 54 [2] 0c 61 [2] 22 61 [2] 1d 7d }

  condition:
    any of them
}