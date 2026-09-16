rule TTP_XOR_WriteProcessMemory_7f54 {
  strings:
    $key_7f54 = { 28 26 [2] 1a 04 [2] 1c 31 [2] 32 31 [2] 0d 2d }

  condition:
    any of them
}