rule TTP_XOR_WriteProcessMemory_48cc {
  strings:
    $key_48cc = { 1f be [2] 2d 9c [2] 2b a9 [2] 05 a9 [2] 3a b5 }

  condition:
    any of them
}