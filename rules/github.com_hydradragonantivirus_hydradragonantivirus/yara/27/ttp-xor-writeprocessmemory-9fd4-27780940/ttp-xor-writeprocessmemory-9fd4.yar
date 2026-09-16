rule TTP_XOR_WriteProcessMemory_9fd4 {
  strings:
    $key_9fd4 = { c8 a6 [2] fa 84 [2] fc b1 [2] d2 b1 [2] ed ad }

  condition:
    any of them
}