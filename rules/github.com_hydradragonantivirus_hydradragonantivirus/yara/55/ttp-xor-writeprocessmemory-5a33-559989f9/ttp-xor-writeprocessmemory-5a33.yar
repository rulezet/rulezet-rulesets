rule TTP_XOR_WriteProcessMemory_5a33 {
  strings:
    $key_5a33 = { 0d 41 [2] 3f 63 [2] 39 56 [2] 17 56 [2] 28 4a }

  condition:
    any of them
}