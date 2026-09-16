rule TTP_XOR_WriteProcessMemory_9fa5 {
  strings:
    $key_9fa5 = { c8 d7 [2] fa f5 [2] fc c0 [2] d2 c0 [2] ed dc }

  condition:
    any of them
}