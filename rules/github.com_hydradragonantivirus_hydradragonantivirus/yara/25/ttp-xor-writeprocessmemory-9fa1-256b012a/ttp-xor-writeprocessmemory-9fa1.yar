rule TTP_XOR_WriteProcessMemory_9fa1 {
  strings:
    $key_9fa1 = { c8 d3 [2] fa f1 [2] fc c4 [2] d2 c4 [2] ed d8 }

  condition:
    any of them
}