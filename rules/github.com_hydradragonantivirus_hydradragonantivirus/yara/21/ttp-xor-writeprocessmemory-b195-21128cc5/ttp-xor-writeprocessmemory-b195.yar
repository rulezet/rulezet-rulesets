rule TTP_XOR_WriteProcessMemory_b195 {
  strings:
    $key_b195 = { e6 e7 [2] d4 c5 [2] d2 f0 [2] fc f0 [2] c3 ec }

  condition:
    any of them
}