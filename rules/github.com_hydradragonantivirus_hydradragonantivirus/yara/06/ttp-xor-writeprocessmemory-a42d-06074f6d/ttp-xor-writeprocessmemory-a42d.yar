rule TTP_XOR_WriteProcessMemory_a42d {
  strings:
    $key_a42d = { f3 5f [2] c1 7d [2] c7 48 [2] e9 48 [2] d6 54 }

  condition:
    any of them
}