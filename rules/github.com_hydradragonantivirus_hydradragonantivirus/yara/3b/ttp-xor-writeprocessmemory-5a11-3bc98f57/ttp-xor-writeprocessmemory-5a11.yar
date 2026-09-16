rule TTP_XOR_WriteProcessMemory_5a11 {
  strings:
    $key_5a11 = { 0d 63 [2] 3f 41 [2] 39 74 [2] 17 74 [2] 28 68 }

  condition:
    any of them
}