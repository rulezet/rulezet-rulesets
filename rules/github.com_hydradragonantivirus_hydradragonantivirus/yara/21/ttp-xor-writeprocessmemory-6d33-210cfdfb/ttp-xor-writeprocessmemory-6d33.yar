rule TTP_XOR_WriteProcessMemory_6d33 {
  strings:
    $key_6d33 = { 3a 41 [2] 08 63 [2] 0e 56 [2] 20 56 [2] 1f 4a }

  condition:
    any of them
}