rule TTP_XOR_WriteProcessMemory_5a54 {
  strings:
    $key_5a54 = { 0d 26 [2] 3f 04 [2] 39 31 [2] 17 31 [2] 28 2d }

  condition:
    any of them
}