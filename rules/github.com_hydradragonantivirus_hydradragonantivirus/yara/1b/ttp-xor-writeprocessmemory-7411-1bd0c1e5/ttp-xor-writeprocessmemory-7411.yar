rule TTP_XOR_WriteProcessMemory_7411 {
  strings:
    $key_7411 = { 23 63 [2] 11 41 [2] 17 74 [2] 39 74 [2] 06 68 }

  condition:
    any of them
}