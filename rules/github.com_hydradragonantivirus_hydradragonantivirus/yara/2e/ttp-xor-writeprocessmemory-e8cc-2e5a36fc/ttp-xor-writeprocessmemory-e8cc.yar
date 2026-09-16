rule TTP_XOR_WriteProcessMemory_e8cc {
  strings:
    $key_e8cc = { bf be [2] 8d 9c [2] 8b a9 [2] a5 a9 [2] 9a b5 }

  condition:
    any of them
}