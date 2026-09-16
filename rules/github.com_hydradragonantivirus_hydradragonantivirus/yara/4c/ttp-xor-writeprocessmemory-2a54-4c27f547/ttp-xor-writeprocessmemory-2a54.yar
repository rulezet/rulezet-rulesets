rule TTP_XOR_WriteProcessMemory_2a54 {
  strings:
    $key_2a54 = { 7d 26 [2] 4f 04 [2] 49 31 [2] 67 31 [2] 58 2d }

  condition:
    any of them
}