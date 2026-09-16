rule TTP_XOR_WriteProcessMemory_8ef1 {
  strings:
    $key_8ef1 = { d9 83 [2] eb a1 [2] ed 94 [2] c3 94 [2] fc 88 }

  condition:
    any of them
}