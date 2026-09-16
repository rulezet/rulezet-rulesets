rule TTP_XOR_WriteProcessMemory_7211 {
  strings:
    $key_7211 = { 25 63 [2] 17 41 [2] 11 74 [2] 3f 74 [2] 00 68 }

  condition:
    any of them
}