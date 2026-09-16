rule TTP_XOR_WriteProcessMemory_8f97 {
  strings:
    $key_8f97 = { d8 e5 [2] ea c7 [2] ec f2 [2] c2 f2 [2] fd ee }

  condition:
    any of them
}