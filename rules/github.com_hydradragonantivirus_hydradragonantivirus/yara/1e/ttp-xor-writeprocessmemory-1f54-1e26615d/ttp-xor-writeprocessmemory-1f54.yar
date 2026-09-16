rule TTP_XOR_WriteProcessMemory_1f54 {
  strings:
    $key_1f54 = { 48 26 [2] 7a 04 [2] 7c 31 [2] 52 31 [2] 6d 2d }

  condition:
    any of them
}