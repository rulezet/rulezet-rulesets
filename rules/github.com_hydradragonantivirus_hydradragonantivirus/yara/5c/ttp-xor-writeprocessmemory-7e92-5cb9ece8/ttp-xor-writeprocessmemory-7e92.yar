rule TTP_XOR_WriteProcessMemory_7e92 {
  strings:
    $key_7e92 = { 29 e0 [2] 1b c2 [2] 1d f7 [2] 33 f7 [2] 0c eb }

  condition:
    any of them
}