rule TTP_XOR_WriteProcessMemory_5893 {
  strings:
    $key_5893 = { 0f e1 [2] 3d c3 [2] 3b f6 [2] 15 f6 [2] 2a ea }

  condition:
    any of them
}