rule TTP_XOR_WriteProcessMemory_d6cd {
  strings:
    $key_d6cd = { 81 bf [2] b3 9d [2] b5 a8 [2] 9b a8 [2] a4 b4 }

  condition:
    any of them
}