rule TTP_XOR_WriteProcessMemory_9fac {
  strings:
    $key_9fac = { c8 de [2] fa fc [2] fc c9 [2] d2 c9 [2] ed d5 }

  condition:
    any of them
}