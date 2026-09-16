rule TTP_XOR_WriteProcessMemory_7a33 {
  strings:
    $key_7a33 = { 2d 41 [2] 1f 63 [2] 19 56 [2] 37 56 [2] 08 4a }

  condition:
    any of them
}