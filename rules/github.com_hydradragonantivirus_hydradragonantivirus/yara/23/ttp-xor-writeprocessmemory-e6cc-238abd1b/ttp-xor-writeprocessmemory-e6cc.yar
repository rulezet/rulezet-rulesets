rule TTP_XOR_WriteProcessMemory_e6cc {
  strings:
    $key_e6cc = { b1 be [2] 83 9c [2] 85 a9 [2] ab a9 [2] 94 b5 }

  condition:
    any of them
}