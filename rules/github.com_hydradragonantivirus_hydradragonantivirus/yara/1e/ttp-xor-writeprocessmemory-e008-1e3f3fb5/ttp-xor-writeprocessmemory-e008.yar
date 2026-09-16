rule TTP_XOR_WriteProcessMemory_e008 {
  strings:
    $key_e008 = { b7 7a [2] 85 58 [2] 83 6d [2] ad 6d [2] 92 71 }

  condition:
    any of them
}