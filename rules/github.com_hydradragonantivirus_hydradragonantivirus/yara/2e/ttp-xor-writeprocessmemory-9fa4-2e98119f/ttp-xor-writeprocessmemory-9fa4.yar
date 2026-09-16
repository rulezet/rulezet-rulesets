rule TTP_XOR_WriteProcessMemory_9fa4 {
  strings:
    $key_9fa4 = { c8 d6 [2] fa f4 [2] fc c1 [2] d2 c1 [2] ed dd }

  condition:
    any of them
}