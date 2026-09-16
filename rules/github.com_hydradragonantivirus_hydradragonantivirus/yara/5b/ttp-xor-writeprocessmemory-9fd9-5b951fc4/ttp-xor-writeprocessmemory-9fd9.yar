rule TTP_XOR_WriteProcessMemory_9fd9 {
  strings:
    $key_9fd9 = { c8 ab [2] fa 89 [2] fc bc [2] d2 bc [2] ed a0 }

  condition:
    any of them
}