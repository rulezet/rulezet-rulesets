rule TTP_XOR_WriteProcessMemory_9fa2 {
  strings:
    $key_9fa2 = { c8 d0 [2] fa f2 [2] fc c7 [2] d2 c7 [2] ed db }

  condition:
    any of them
}