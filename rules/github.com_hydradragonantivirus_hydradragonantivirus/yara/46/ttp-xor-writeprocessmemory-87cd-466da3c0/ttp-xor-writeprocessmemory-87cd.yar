rule TTP_XOR_WriteProcessMemory_87cd {
  strings:
    $key_87cd = { d0 bf [2] e2 9d [2] e4 a8 [2] ca a8 [2] f5 b4 }

  condition:
    any of them
}