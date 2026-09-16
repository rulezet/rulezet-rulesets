rule TTP_XOR_WriteProcessMemory_8eab {
  strings:
    $key_8eab = { d9 d9 [2] eb fb [2] ed ce [2] c3 ce [2] fc d2 }

  condition:
    any of them
}