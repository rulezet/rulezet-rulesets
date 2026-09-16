rule TTP_XOR_WriteProcessMemory_8668 {
  strings:
    $key_8668 = { d1 1a [2] e3 38 [2] e5 0d [2] cb 0d [2] f4 11 }

  condition:
    any of them
}