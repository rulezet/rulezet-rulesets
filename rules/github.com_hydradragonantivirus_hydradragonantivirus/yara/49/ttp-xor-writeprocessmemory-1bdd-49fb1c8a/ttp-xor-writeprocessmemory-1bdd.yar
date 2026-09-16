rule TTP_XOR_WriteProcessMemory_1bdd {
  strings:
    $key_1bdd = { 4c af [2] 7e 8d [2] 78 b8 [2] 56 b8 [2] 69 a4 }

  condition:
    any of them
}