rule TTP_XOR_WriteProcessMemory_a2cd {
  strings:
    $key_a2cd = { f5 bf [2] c7 9d [2] c1 a8 [2] ef a8 [2] d0 b4 }

  condition:
    any of them
}