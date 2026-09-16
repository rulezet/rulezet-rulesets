rule TTP_XOR_WriteProcessMemory_6f33 {
  strings:
    $key_6f33 = { 38 41 [2] 0a 63 [2] 0c 56 [2] 22 56 [2] 1d 4a }

  condition:
    any of them
}