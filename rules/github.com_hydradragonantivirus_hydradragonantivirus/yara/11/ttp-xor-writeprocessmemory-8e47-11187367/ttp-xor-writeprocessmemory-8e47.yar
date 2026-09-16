rule TTP_XOR_WriteProcessMemory_8e47 {
  strings:
    $key_8e47 = { d9 35 [2] eb 17 [2] ed 22 [2] c3 22 [2] fc 3e }

  condition:
    any of them
}