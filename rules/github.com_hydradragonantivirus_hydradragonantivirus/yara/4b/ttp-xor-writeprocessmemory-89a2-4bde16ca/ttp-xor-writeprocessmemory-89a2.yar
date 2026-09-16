rule TTP_XOR_WriteProcessMemory_89a2 {
  strings:
    $key_89a2 = { de d0 [2] ec f2 [2] ea c7 [2] c4 c7 [2] fb db }

  condition:
    any of them
}