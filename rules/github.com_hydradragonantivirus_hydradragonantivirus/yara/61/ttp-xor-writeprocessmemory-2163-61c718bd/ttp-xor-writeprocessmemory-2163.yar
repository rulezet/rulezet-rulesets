rule TTP_XOR_WriteProcessMemory_2163 {
  strings:
    $key_2163 = { 76 11 [2] 44 33 [2] 42 06 [2] 6c 06 [2] 53 1a }

  condition:
    any of them
}