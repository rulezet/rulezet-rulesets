rule TTP_XOR_WriteProcessMemory_86e8 {
  strings:
    $key_86e8 = { d1 9a [2] e3 b8 [2] e5 8d [2] cb 8d [2] f4 91 }

  condition:
    any of them
}