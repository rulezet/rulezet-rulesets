rule TTP_XOR_WriteProcessMemory_9fa6 {
  strings:
    $key_9fa6 = { c8 d4 [2] fa f6 [2] fc c3 [2] d2 c3 [2] ed df }

  condition:
    any of them
}