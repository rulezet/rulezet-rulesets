rule TTP_XOR_WriteProcessMemory_7a73 {
  strings:
    $key_7a73 = { 2d 01 [2] 1f 23 [2] 19 16 [2] 37 16 [2] 08 0a }

  condition:
    any of them
}