rule TTP_XOR_WriteProcessMemory_8f40 {
  strings:
    $key_8f40 = { d8 32 [2] ea 10 [2] ec 25 [2] c2 25 [2] fd 39 }

  condition:
    any of them
}