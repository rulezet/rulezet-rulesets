rule TTP_XOR_WriteProcessMemory_8e35 {
  strings:
    $key_8e35 = { d9 47 [2] eb 65 [2] ed 50 [2] c3 50 [2] fc 4c }

  condition:
    any of them
}