rule TTP_XOR_WriteProcessMemory_9fad {
  strings:
    $key_9fad = { c8 df [2] fa fd [2] fc c8 [2] d2 c8 [2] ed d4 }

  condition:
    any of them
}