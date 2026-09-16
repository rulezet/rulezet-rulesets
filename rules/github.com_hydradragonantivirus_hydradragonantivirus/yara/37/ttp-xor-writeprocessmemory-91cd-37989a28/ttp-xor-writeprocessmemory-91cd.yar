rule TTP_XOR_WriteProcessMemory_91cd {
  strings:
    $key_91cd = { c6 bf [2] f4 9d [2] f2 a8 [2] dc a8 [2] e3 b4 }

  condition:
    any of them
}