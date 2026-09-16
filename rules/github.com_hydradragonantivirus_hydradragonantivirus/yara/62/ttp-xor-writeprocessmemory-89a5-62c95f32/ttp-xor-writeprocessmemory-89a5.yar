rule TTP_XOR_WriteProcessMemory_89a5 {
  strings:
    $key_89a5 = { de d7 [2] ec f5 [2] ea c0 [2] c4 c0 [2] fb dc }

  condition:
    any of them
}