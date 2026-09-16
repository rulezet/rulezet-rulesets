rule TTP_XOR_WriteProcessMemory_6708 {
  strings:
    $key_6708 = { 30 7a [2] 02 58 [2] 04 6d [2] 2a 6d [2] 15 71 }

  condition:
    any of them
}