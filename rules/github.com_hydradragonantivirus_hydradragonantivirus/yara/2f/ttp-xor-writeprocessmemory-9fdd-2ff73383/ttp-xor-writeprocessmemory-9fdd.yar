rule TTP_XOR_WriteProcessMemory_9fdd {
  strings:
    $key_9fdd = { c8 af [2] fa 8d [2] fc b8 [2] d2 b8 [2] ed a4 }

  condition:
    any of them
}