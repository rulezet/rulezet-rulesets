rule TTP_XOR_WriteProcessMemory_0279 {
  strings:
    $key_0279 = { 55 0b [2] 67 29 [2] 61 1c [2] 4f 1c [2] 70 00 }

  condition:
    any of them
}