rule TTP_XOR_WriteProcessMemory_b193 {
  strings:
    $key_b193 = { e6 e1 [2] d4 c3 [2] d2 f6 [2] fc f6 [2] c3 ea }

  condition:
    any of them
}