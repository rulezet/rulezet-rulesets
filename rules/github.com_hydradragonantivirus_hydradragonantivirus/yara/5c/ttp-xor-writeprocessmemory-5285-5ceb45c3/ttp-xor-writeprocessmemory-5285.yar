rule TTP_XOR_WriteProcessMemory_5285 {
  strings:
    $key_5285 = { 05 f7 [2] 37 d5 [2] 31 e0 [2] 1f e0 [2] 20 fc }

  condition:
    any of them
}