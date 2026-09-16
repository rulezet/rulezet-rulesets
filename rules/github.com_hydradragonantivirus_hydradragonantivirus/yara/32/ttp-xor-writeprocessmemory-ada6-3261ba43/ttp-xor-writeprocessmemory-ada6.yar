rule TTP_XOR_WriteProcessMemory_ada6 {
  strings:
    $key_ada6 = { fa d4 [2] c8 f6 [2] ce c3 [2] e0 c3 [2] df df }

  condition:
    any of them
}