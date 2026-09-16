rule TTP_XOR_WriteProcessMemory_add5 {
  strings:
    $key_add5 = { fa a7 [2] c8 85 [2] ce b0 [2] e0 b0 [2] df ac }

  condition:
    any of them
}