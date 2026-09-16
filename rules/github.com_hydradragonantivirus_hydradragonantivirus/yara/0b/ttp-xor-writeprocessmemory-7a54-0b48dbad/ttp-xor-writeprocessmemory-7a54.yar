rule TTP_XOR_WriteProcessMemory_7a54 {
  strings:
    $key_7a54 = { 2d 26 [2] 1f 04 [2] 19 31 [2] 37 31 [2] 08 2d }

  condition:
    any of them
}