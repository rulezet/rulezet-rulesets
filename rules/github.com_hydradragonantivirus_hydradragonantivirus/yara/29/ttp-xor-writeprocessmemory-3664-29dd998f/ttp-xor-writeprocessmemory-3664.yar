rule TTP_XOR_WriteProcessMemory_3664 {
  strings:
    $key_3664 = { 61 16 [2] 53 34 [2] 55 01 [2] 7b 01 [2] 44 1d }

  condition:
    any of them
}