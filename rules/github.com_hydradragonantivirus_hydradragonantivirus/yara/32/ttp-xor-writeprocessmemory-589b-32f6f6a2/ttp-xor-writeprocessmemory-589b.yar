rule TTP_XOR_WriteProcessMemory_589b {
  strings:
    $key_589b = { 0f e9 [2] 3d cb [2] 3b fe [2] 15 fe [2] 2a e2 }

  condition:
    any of them
}