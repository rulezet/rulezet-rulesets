rule TTP_XOR_WriteProcessMemory_b260 {
  strings:
    $key_b260 = { e5 12 [2] d7 30 [2] d1 05 [2] ff 05 [2] c0 19 }

  condition:
    any of them
}