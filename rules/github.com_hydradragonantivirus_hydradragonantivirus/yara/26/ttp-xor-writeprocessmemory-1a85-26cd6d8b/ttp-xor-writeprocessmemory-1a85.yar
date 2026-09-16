rule TTP_XOR_WriteProcessMemory_1a85 {
  strings:
    $key_1a85 = { 4d f7 [2] 7f d5 [2] 79 e0 [2] 57 e0 [2] 68 fc }

  condition:
    any of them
}