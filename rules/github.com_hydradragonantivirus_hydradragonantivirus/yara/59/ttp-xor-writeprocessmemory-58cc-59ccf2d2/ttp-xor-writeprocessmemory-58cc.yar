rule TTP_XOR_WriteProcessMemory_58cc {
  strings:
    $key_58cc = { 0f be [2] 3d 9c [2] 3b a9 [2] 15 a9 [2] 2a b5 }

  condition:
    any of them
}