rule TTP_XOR_WriteProcessMemory_a40d {
  strings:
    $key_a40d = { f3 7f [2] c1 5d [2] c7 68 [2] e9 68 [2] d6 74 }

  condition:
    any of them
}