rule TTP_XOR_WriteProcessMemory_0479 {
  strings:
    $key_0479 = { 53 0b [2] 61 29 [2] 67 1c [2] 49 1c [2] 76 00 }

  condition:
    any of them
}