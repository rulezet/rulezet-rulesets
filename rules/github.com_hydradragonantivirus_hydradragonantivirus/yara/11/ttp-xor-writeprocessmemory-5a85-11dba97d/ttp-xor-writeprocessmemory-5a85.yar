rule TTP_XOR_WriteProcessMemory_5a85 {
  strings:
    $key_5a85 = { 0d f7 [2] 3f d5 [2] 39 e0 [2] 17 e0 [2] 28 fc }

  condition:
    any of them
}