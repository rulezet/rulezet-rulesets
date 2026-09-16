rule TTP_XOR_WriteProcessMemory_a42c {
  strings:
    $key_a42c = { f3 5e [2] c1 7c [2] c7 49 [2] e9 49 [2] d6 55 }

  condition:
    any of them
}