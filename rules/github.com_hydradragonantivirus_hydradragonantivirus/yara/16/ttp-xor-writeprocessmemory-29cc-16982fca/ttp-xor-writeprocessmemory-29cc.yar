rule TTP_XOR_WriteProcessMemory_29cc {
  strings:
    $key_29cc = { 7e be [2] 4c 9c [2] 4a a9 [2] 64 a9 [2] 5b b5 }

  condition:
    any of them
}