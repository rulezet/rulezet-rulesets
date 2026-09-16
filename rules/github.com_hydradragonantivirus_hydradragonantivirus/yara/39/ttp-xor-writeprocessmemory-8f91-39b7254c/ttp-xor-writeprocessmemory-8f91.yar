rule TTP_XOR_WriteProcessMemory_8f91 {
  strings:
    $key_8f91 = { d8 e3 [2] ea c1 [2] ec f4 [2] c2 f4 [2] fd e8 }

  condition:
    any of them
}