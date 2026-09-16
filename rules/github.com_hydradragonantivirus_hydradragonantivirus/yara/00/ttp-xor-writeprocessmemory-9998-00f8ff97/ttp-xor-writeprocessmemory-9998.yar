rule TTP_XOR_WriteProcessMemory_9998 {
  strings:
    $key_9998 = { ce ea [2] fc c8 [2] fa fd [2] d4 fd [2] eb e1 }

  condition:
    any of them
}