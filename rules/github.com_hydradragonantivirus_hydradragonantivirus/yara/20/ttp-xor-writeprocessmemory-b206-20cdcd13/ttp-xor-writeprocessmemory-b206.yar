rule TTP_XOR_WriteProcessMemory_b206 {
  strings:
    $key_b206 = { e5 74 [2] d7 56 [2] d1 63 [2] ff 63 [2] c0 7f }

  condition:
    any of them
}