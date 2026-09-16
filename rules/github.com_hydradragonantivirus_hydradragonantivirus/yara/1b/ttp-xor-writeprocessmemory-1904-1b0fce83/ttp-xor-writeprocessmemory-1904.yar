rule TTP_XOR_WriteProcessMemory_1904 {
  strings:
    $key_1904 = { 4e 76 [2] 7c 54 [2] 7a 61 [2] 54 61 [2] 6b 7d }

  condition:
    any of them
}