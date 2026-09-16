rule TTP_XOR_WriteProcessMemory_a5cd {
  strings:
    $key_a5cd = { f2 bf [2] c0 9d [2] c6 a8 [2] e8 a8 [2] d7 b4 }

  condition:
    any of them
}