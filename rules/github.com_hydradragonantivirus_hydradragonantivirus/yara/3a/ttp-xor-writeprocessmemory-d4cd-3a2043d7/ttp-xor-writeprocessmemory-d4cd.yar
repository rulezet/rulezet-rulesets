rule TTP_XOR_WriteProcessMemory_d4cd {
  strings:
    $key_d4cd = { 83 bf [2] b1 9d [2] b7 a8 [2] 99 a8 [2] a6 b4 }

  condition:
    any of them
}