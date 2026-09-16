rule TTP_XOR_WriteProcessMemory_b247 {
  strings:
    $key_b247 = { e5 35 [2] d7 17 [2] d1 22 [2] ff 22 [2] c0 3e }

  condition:
    any of them
}