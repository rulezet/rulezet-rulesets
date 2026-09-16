rule TTP_XOR_WriteProcessMemory_86fb {
  strings:
    $key_86fb = { d1 89 [2] e3 ab [2] e5 9e [2] cb 9e [2] f4 82 }

  condition:
    any of them
}