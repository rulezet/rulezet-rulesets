rule TTP_XOR_WriteProcessMemory_4a11 {
  strings:
    $key_4a11 = { 1d 63 [2] 2f 41 [2] 29 74 [2] 07 74 [2] 38 68 }

  condition:
    any of them
}