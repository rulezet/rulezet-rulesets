rule TTP_XOR_WriteProcessMemory_b227 {
  strings:
    $key_b227 = { e5 55 [2] d7 77 [2] d1 42 [2] ff 42 [2] c0 5e }

  condition:
    any of them
}