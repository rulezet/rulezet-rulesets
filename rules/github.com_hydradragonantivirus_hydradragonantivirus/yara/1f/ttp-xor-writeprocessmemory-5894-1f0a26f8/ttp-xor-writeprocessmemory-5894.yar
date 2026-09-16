rule TTP_XOR_WriteProcessMemory_5894 {
  strings:
    $key_5894 = { 0f e6 [2] 3d c4 [2] 3b f1 [2] 15 f1 [2] 2a ed }

  condition:
    any of them
}