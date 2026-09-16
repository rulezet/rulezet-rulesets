rule TTP_XOR_WriteProcessMemory_0708 {
  strings:
    $key_0708 = { 50 7a [2] 62 58 [2] 64 6d [2] 4a 6d [2] 75 71 }

  condition:
    any of them
}