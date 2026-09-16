rule TTP_XOR_WriteProcessMemory_ada0 {
  strings:
    $key_ada0 = { fa d2 [2] c8 f0 [2] ce c5 [2] e0 c5 [2] df d9 }

  condition:
    any of them
}