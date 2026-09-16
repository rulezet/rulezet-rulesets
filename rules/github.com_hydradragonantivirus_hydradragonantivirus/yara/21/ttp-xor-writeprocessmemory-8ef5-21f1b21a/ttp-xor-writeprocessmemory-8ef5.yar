rule TTP_XOR_WriteProcessMemory_8ef5 {
  strings:
    $key_8ef5 = { d9 87 [2] eb a5 [2] ed 90 [2] c3 90 [2] fc 8c }

  condition:
    any of them
}