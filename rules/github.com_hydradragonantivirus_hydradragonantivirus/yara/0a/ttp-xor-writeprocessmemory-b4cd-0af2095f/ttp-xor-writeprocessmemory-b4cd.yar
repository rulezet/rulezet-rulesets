rule TTP_XOR_WriteProcessMemory_b4cd {
  strings:
    $key_b4cd = { e3 bf [2] d1 9d [2] d7 a8 [2] f9 a8 [2] c6 b4 }

  condition:
    any of them
}