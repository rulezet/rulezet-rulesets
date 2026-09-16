rule TTP_XOR_WriteProcessMemory_5508 {
  strings:
    $key_5508 = { 02 7a [2] 30 58 [2] 36 6d [2] 18 6d [2] 27 71 }

  condition:
    any of them
}