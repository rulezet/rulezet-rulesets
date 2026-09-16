rule TTP_XOR_WriteProcessMemory_7896 {
  strings:
    $key_7896 = { 2f e4 [2] 1d c6 [2] 1b f3 [2] 35 f3 [2] 0a ef }

  condition:
    any of them
}