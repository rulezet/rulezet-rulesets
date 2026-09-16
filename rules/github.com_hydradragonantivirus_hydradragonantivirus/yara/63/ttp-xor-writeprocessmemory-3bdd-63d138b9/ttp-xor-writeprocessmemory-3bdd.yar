rule TTP_XOR_WriteProcessMemory_3bdd {
  strings:
    $key_3bdd = { 6c af [2] 5e 8d [2] 58 b8 [2] 76 b8 [2] 49 a4 }

  condition:
    any of them
}