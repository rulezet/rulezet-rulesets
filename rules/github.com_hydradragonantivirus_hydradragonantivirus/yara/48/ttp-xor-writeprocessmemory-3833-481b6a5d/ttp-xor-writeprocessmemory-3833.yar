rule TTP_XOR_WriteProcessMemory_3833 {
  strings:
    $key_3833 = { 6f 41 [2] 5d 63 [2] 5b 56 [2] 75 56 [2] 4a 4a }

  condition:
    any of them
}