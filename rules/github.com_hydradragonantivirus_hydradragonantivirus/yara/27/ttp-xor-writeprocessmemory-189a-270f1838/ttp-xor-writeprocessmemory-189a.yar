rule TTP_XOR_WriteProcessMemory_189a {
  strings:
    $key_189a = { 4f e8 [2] 7d ca [2] 7b ff [2] 55 ff [2] 6a e3 }

  condition:
    any of them
}