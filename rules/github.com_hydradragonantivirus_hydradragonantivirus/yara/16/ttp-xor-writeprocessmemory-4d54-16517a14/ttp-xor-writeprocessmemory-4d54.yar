rule TTP_XOR_WriteProcessMemory_4d54 {
  strings:
    $key_4d54 = { 1a 26 [2] 28 04 [2] 2e 31 [2] 00 31 [2] 3f 2d }

  condition:
    any of them
}