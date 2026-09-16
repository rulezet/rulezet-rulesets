rule TTP_XOR_WriteProcessMemory_7861 {
  strings:
    $key_7861 = { 2f 13 [2] 1d 31 [2] 1b 04 [2] 35 04 [2] 0a 18 }

  condition:
    any of them
}