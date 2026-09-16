rule TTP_XOR_WriteProcessMemory_0e13 {
  strings:
    $key_0e13 = { 59 61 [2] 6b 43 [2] 6d 76 [2] 43 76 [2] 7c 6a }

  condition:
    any of them
}