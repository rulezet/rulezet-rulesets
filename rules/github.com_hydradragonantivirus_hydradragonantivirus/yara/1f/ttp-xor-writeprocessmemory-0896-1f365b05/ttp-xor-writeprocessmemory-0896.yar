rule TTP_XOR_WriteProcessMemory_0896 {
  strings:
    $key_0896 = { 5f e4 [2] 6d c6 [2] 6b f3 [2] 45 f3 [2] 7a ef }

  condition:
    any of them
}