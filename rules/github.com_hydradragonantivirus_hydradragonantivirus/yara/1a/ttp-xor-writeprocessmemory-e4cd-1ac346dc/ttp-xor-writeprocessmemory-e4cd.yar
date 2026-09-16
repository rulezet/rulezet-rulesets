rule TTP_XOR_WriteProcessMemory_e4cd {
  strings:
    $key_e4cd = { b3 bf [2] 81 9d [2] 87 a8 [2] a9 a8 [2] 96 b4 }

  condition:
    any of them
}