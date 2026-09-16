rule TTP_XOR_WriteProcessMemory_b2f8 {
  strings:
    $key_b2f8 = { e5 8a [2] d7 a8 [2] d1 9d [2] ff 9d [2] c0 81 }

  condition:
    any of them
}