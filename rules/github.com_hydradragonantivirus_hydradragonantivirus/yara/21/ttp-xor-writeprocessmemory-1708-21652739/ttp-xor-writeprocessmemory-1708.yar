rule TTP_XOR_WriteProcessMemory_1708 {
  strings:
    $key_1708 = { 40 7a [2] 72 58 [2] 74 6d [2] 5a 6d [2] 65 71 }

  condition:
    any of them
}