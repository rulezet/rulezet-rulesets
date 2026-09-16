rule TTP_XOR_WriteProcessMemory_0608 {
  strings:
    $key_0608 = { 51 7a [2] 63 58 [2] 65 6d [2] 4b 6d [2] 74 71 }

  condition:
    any of them
}