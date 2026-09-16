rule TTP_XOR_WriteProcessMemory_b201 {
  strings:
    $key_b201 = { e5 73 [2] d7 51 [2] d1 64 [2] ff 64 [2] c0 78 }

  condition:
    any of them
}