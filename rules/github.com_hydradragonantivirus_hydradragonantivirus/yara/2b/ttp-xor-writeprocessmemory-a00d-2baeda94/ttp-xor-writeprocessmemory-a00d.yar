rule TTP_XOR_WriteProcessMemory_a00d {
  strings:
    $key_a00d = { f7 7f [2] c5 5d [2] c3 68 [2] ed 68 [2] d2 74 }

  condition:
    any of them
}