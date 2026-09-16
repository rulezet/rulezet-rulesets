rule TTP_XOR_WriteProcessMemory_81c6 {
  strings:
    $key_81c6 = { d6 b4 [2] e4 96 [2] e2 a3 [2] cc a3 [2] f3 bf }

  condition:
    any of them
}