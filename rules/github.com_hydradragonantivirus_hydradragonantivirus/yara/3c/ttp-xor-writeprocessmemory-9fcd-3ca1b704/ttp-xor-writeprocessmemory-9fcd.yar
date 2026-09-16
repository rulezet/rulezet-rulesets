rule TTP_XOR_WriteProcessMemory_9fcd {
  strings:
    $key_9fcd = { c8 bf [2] fa 9d [2] fc a8 [2] d2 a8 [2] ed b4 }

  condition:
    any of them
}