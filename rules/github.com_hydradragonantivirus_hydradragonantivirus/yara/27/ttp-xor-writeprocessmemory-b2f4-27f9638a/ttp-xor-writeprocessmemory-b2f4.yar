rule TTP_XOR_WriteProcessMemory_b2f4 {
  strings:
    $key_b2f4 = { e5 86 [2] d7 a4 [2] d1 91 [2] ff 91 [2] c0 8d }

  condition:
    any of them
}