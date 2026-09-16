rule TTP_XOR_WriteProcessMemory_b203 {
  strings:
    $key_b203 = { e5 71 [2] d7 53 [2] d1 66 [2] ff 66 [2] c0 7a }

  condition:
    any of them
}