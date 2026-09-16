rule TTP_XOR_WriteProcessMemory_8f22 {
  strings:
    $key_8f22 = { d8 50 [2] ea 72 [2] ec 47 [2] c2 47 [2] fd 5b }

  condition:
    any of them
}