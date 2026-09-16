rule TTP_XOR_WriteProcessMemory_4a53 {
  strings:
    $key_4a53 = { 1d 21 [2] 2f 03 [2] 29 36 [2] 07 36 [2] 38 2a }

  condition:
    any of them
}