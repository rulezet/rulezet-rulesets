rule TTP_XOR_WriteProcessMemory_489a {
  strings:
    $key_489a = { 1f e8 [2] 2d ca [2] 2b ff [2] 05 ff [2] 3a e3 }

  condition:
    any of them
}