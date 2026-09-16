rule TTP_XOR_WriteProcessMemory_83ba {
  strings:
    $key_83ba = { d4 c8 [2] e6 ea [2] e0 df [2] ce df [2] f1 c3 }

  condition:
    any of them
}