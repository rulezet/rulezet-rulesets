rule TTP_XOR_WriteProcessMemory_b228 {
  strings:
    $key_b228 = { e5 5a [2] d7 78 [2] d1 4d [2] ff 4d [2] c0 51 }

  condition:
    any of them
}