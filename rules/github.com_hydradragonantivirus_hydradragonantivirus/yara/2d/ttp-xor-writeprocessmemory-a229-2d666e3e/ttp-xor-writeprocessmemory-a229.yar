rule TTP_XOR_WriteProcessMemory_a229 {
  strings:
    $key_a229 = { f5 5b [2] c7 79 [2] c1 4c [2] ef 4c [2] d0 50 }

  condition:
    any of them
}