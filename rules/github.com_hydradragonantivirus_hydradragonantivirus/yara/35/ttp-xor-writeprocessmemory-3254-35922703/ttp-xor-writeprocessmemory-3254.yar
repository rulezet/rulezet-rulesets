rule TTP_XOR_WriteProcessMemory_3254 {
  strings:
    $key_3254 = { 65 26 [2] 57 04 [2] 51 31 [2] 7f 31 [2] 40 2d }

  condition:
    any of them
}