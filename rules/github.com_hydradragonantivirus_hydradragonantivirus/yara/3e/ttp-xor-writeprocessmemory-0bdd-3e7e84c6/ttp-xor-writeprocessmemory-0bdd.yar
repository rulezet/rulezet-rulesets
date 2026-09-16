rule TTP_XOR_WriteProcessMemory_0bdd {
  strings:
    $key_0bdd = { 5c af [2] 6e 8d [2] 68 b8 [2] 46 b8 [2] 79 a4 }

  condition:
    any of them
}