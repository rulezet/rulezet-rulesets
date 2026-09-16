rule TTP_XOR_WriteProcessMemory_9fc1 {
  strings:
    $key_9fc1 = { c8 b3 [2] fa 91 [2] fc a4 [2] d2 a4 [2] ed b8 }

  condition:
    any of them
}