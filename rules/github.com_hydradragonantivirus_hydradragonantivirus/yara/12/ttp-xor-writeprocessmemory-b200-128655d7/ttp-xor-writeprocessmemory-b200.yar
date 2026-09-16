rule TTP_XOR_WriteProcessMemory_b200 {
  strings:
    $key_b200 = { e5 72 [2] d7 50 [2] d1 65 [2] ff 65 [2] c0 79 }

  condition:
    any of them
}