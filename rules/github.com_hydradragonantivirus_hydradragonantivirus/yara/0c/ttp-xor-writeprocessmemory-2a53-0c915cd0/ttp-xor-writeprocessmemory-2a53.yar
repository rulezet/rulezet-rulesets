rule TTP_XOR_WriteProcessMemory_2a53 {
  strings:
    $key_2a53 = { 7d 21 [2] 4f 03 [2] 49 36 [2] 67 36 [2] 58 2a }

  condition:
    any of them
}