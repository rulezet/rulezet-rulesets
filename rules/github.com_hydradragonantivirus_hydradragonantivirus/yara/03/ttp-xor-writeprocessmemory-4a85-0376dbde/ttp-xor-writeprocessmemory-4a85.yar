rule TTP_XOR_WriteProcessMemory_4a85 {
  strings:
    $key_4a85 = { 1d f7 [2] 2f d5 [2] 29 e0 [2] 07 e0 [2] 38 fc }

  condition:
    any of them
}