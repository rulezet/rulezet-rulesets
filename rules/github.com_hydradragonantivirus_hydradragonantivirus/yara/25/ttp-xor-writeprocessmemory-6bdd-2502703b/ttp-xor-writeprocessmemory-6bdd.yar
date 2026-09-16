rule TTP_XOR_WriteProcessMemory_6bdd {
  strings:
    $key_6bdd = { 3c af [2] 0e 8d [2] 08 b8 [2] 26 b8 [2] 19 a4 }

  condition:
    any of them
}