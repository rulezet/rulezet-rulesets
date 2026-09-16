rule TTP_XOR_WriteProcessMemory_b430 {
  strings:
    $key_b430 = { e3 42 [2] d1 60 [2] d7 55 [2] f9 55 [2] c6 49 }

  condition:
    any of them
}