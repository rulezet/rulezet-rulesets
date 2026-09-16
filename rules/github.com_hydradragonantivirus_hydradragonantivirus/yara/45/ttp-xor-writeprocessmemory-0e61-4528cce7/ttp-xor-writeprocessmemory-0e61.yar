rule TTP_XOR_WriteProcessMemory_0e61 {
  strings:
    $key_0e61 = { 59 13 [2] 6b 31 [2] 6d 04 [2] 43 04 [2] 7c 18 }

  condition:
    any of them
}