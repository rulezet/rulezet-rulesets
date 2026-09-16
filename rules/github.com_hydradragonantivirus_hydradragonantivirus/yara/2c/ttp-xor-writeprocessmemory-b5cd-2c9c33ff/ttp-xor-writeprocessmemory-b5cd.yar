rule TTP_XOR_WriteProcessMemory_b5cd {
  strings:
    $key_b5cd = { e2 bf [2] d0 9d [2] d6 a8 [2] f8 a8 [2] c7 b4 }

  condition:
    any of them
}