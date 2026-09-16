rule TTP_XOR_WriteProcessMemory_3f54 {
  strings:
    $key_3f54 = { 68 26 [2] 5a 04 [2] 5c 31 [2] 72 31 [2] 4d 2d }

  condition:
    any of them
}