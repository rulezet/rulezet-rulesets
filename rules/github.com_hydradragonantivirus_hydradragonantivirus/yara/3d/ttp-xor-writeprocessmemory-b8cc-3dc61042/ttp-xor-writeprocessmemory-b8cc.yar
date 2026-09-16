rule TTP_XOR_WriteProcessMemory_b8cc {
  strings:
    $key_b8cc = { ef be [2] dd 9c [2] db a9 [2] f5 a9 [2] ca b5 }

  condition:
    any of them
}