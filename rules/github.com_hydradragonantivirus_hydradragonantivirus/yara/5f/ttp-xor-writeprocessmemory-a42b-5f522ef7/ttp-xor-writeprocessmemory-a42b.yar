rule TTP_XOR_WriteProcessMemory_a42b {
  strings:
    $key_a42b = { f3 59 [2] c1 7b [2] c7 4e [2] e9 4e [2] d6 52 }

  condition:
    any of them
}