rule TTP_XOR_WriteProcessMemory_8f86 {
  strings:
    $key_8f86 = { d8 f4 [2] ea d6 [2] ec e3 [2] c2 e3 [2] fd ff }

  condition:
    any of them
}