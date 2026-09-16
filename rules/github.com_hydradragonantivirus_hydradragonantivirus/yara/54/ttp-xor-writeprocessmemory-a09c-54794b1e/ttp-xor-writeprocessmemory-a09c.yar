rule TTP_XOR_WriteProcessMemory_a09c {
  strings:
    $key_a09c = { f7 ee [2] c5 cc [2] c3 f9 [2] ed f9 [2] d2 e5 }

  condition:
    any of them
}