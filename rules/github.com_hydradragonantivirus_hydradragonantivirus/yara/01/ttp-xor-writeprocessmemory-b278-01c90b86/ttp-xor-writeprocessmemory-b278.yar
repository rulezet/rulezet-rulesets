rule TTP_XOR_WriteProcessMemory_b278 {
  strings:
    $key_b278 = { e5 0a [2] d7 28 [2] d1 1d [2] ff 1d [2] c0 01 }

  condition:
    any of them
}