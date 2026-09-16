rule TTP_XOR_WriteProcessMemory_589a {
  strings:
    $key_589a = { 0f e8 [2] 3d ca [2] 3b ff [2] 15 ff [2] 2a e3 }

  condition:
    any of them
}