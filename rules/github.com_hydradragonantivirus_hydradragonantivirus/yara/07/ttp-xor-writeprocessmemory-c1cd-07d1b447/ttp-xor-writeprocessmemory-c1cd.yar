rule TTP_XOR_WriteProcessMemory_c1cd {
  strings:
    $key_c1cd = { 96 bf [2] a4 9d [2] a2 a8 [2] 8c a8 [2] b3 b4 }

  condition:
    any of them
}