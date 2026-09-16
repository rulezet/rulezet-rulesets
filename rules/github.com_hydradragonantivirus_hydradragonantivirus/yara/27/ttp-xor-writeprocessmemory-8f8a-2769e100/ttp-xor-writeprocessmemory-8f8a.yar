rule TTP_XOR_WriteProcessMemory_8f8a {
  strings:
    $key_8f8a = { d8 f8 [2] ea da [2] ec ef [2] c2 ef [2] fd f3 }

  condition:
    any of them
}