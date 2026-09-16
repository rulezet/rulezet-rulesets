rule TTP_XOR_WriteProcessMemory_a095 {
  strings:
    $key_a095 = { f7 e7 [2] c5 c5 [2] c3 f0 [2] ed f0 [2] d2 ec }

  condition:
    any of them
}