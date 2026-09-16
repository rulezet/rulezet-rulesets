rule TTP_XOR_WriteProcessMemory_b270 {
  strings:
    $key_b270 = { e5 02 [2] d7 20 [2] d1 15 [2] ff 15 [2] c0 09 }

  condition:
    any of them
}