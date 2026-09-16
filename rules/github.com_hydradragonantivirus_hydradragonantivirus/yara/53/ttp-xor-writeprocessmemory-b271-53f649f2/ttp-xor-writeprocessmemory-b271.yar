rule TTP_XOR_WriteProcessMemory_b271 {
  strings:
    $key_b271 = { e5 03 [2] d7 21 [2] d1 14 [2] ff 14 [2] c0 08 }

  condition:
    any of them
}