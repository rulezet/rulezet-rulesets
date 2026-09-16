rule TTP_XOR_WriteProcessMemory_4bdd {
  strings:
    $key_4bdd = { 1c af [2] 2e 8d [2] 28 b8 [2] 06 b8 [2] 39 a4 }

  condition:
    any of them
}