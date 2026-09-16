rule TTP_XOR_WriteProcessMemory_b2e3 {
  strings:
    $key_b2e3 = { e5 91 [2] d7 b3 [2] d1 86 [2] ff 86 [2] c0 9a }

  condition:
    any of them
}