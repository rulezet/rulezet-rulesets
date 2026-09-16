rule TTP_XOR_WriteProcessMemory_8f8d {
  strings:
    $key_8f8d = { d8 ff [2] ea dd [2] ec e8 [2] c2 e8 [2] fd f4 }

  condition:
    any of them
}