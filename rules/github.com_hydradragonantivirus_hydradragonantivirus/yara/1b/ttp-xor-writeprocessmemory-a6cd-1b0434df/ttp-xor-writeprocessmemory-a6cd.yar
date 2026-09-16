rule TTP_XOR_WriteProcessMemory_a6cd {
  strings:
    $key_a6cd = { f1 bf [2] c3 9d [2] c5 a8 [2] eb a8 [2] d4 b4 }

  condition:
    any of them
}