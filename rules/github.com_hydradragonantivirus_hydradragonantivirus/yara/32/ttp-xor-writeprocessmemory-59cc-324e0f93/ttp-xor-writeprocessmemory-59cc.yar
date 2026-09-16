rule TTP_XOR_WriteProcessMemory_59cc {
  strings:
    $key_59cc = { 0e be [2] 3c 9c [2] 3a a9 [2] 14 a9 [2] 2b b5 }

  condition:
    any of them
}