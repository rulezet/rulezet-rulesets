rule TTP_XOR_WriteProcessMemory_1892 {
  strings:
    $key_1892 = { 4f e0 [2] 7d c2 [2] 7b f7 [2] 55 f7 [2] 6a eb }

  condition:
    any of them
}