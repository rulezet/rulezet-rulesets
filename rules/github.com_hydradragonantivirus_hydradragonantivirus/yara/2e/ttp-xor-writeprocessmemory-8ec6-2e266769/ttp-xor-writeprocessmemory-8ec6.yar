rule TTP_XOR_WriteProcessMemory_8ec6 {
  strings:
    $key_8ec6 = { d9 b4 [2] eb 96 [2] ed a3 [2] c3 a3 [2] fc bf }

  condition:
    any of them
}