rule TTP_XOR_WriteProcessMemory_9fc5 {
  strings:
    $key_9fc5 = { c8 b7 [2] fa 95 [2] fc a0 [2] d2 a0 [2] ed bc }

  condition:
    any of them
}