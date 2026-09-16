rule TTP_XOR_WriteProcessMemory_98b8 {
  strings:
    $key_98b8 = { cf ca [2] fd e8 [2] fb dd [2] d5 dd [2] ea c1 }

  condition:
    any of them
}