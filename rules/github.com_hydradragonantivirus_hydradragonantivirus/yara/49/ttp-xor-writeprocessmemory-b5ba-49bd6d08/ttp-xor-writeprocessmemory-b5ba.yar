rule TTP_XOR_WriteProcessMemory_b5ba {
  strings:
    $key_b5ba = { e2 c8 [2] d0 ea [2] d6 df [2] f8 df [2] c7 c3 }

  condition:
    any of them
}