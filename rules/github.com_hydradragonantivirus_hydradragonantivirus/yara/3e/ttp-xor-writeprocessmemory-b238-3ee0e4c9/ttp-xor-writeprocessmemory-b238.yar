rule TTP_XOR_WriteProcessMemory_b238 {
  strings:
    $key_b238 = { e5 4a [2] d7 68 [2] d1 5d [2] ff 5d [2] c0 41 }

  condition:
    any of them
}