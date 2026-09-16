rule TTP_XOR_WriteProcessMemory_ada2 {
  strings:
    $key_ada2 = { fa d0 [2] c8 f2 [2] ce c7 [2] e0 c7 [2] df db }

  condition:
    any of them
}