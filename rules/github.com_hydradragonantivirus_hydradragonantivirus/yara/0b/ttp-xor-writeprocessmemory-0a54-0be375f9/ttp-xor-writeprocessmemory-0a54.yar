rule TTP_XOR_WriteProcessMemory_0a54 {
  strings:
    $key_0a54 = { 5d 26 [2] 6f 04 [2] 69 31 [2] 47 31 [2] 78 2d }

  condition:
    any of them
}