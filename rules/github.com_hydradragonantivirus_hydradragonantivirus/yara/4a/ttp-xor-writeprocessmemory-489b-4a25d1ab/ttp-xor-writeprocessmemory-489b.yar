rule TTP_XOR_WriteProcessMemory_489b {
  strings:
    $key_489b = { 1f e9 [2] 2d cb [2] 2b fe [2] 05 fe [2] 3a e2 }

  condition:
    any of them
}