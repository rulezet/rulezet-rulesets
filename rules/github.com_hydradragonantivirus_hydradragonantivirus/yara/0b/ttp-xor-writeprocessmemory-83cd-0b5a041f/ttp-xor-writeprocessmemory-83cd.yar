rule TTP_XOR_WriteProcessMemory_83cd {
  strings:
    $key_83cd = { d4 bf [2] e6 9d [2] e0 a8 [2] ce a8 [2] f1 b4 }

  condition:
    any of them
}