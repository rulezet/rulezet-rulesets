rule TTP_XOR_WriteProcessMemory_9fd0 {
  strings:
    $key_9fd0 = { c8 a2 [2] fa 80 [2] fc b5 [2] d2 b5 [2] ed a9 }

  condition:
    any of them
}