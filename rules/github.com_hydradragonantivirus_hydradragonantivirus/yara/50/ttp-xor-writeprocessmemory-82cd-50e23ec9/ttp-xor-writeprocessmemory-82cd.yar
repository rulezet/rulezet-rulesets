rule TTP_XOR_WriteProcessMemory_82cd {
  strings:
    $key_82cd = { d5 bf [2] e7 9d [2] e1 a8 [2] cf a8 [2] f0 b4 }

  condition:
    any of them
}