rule TTP_XOR_WriteProcessMemory_d1cd {
  strings:
    $key_d1cd = { 86 bf [2] b4 9d [2] b2 a8 [2] 9c a8 [2] a3 b4 }

  condition:
    any of them
}