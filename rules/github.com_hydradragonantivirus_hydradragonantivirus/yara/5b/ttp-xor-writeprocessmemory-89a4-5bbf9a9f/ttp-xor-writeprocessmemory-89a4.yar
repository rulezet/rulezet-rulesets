rule TTP_XOR_WriteProcessMemory_89a4 {
  strings:
    $key_89a4 = { de d6 [2] ec f4 [2] ea c1 [2] c4 c1 [2] fb dd }

  condition:
    any of them
}