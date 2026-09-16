rule TTP_XOR_WriteProcessMemory_4a24 {
  strings:
    $key_4a24 = { 1d 56 [2] 2f 74 [2] 29 41 [2] 07 41 [2] 38 5d }

  condition:
    any of them
}