rule TTP_XOR_WriteProcessMemory_7654 {
  strings:
    $key_7654 = { 21 26 [2] 13 04 [2] 15 31 [2] 3b 31 [2] 04 2d }

  condition:
    any of them
}