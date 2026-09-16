rule TTP_XOR_WriteProcessMemory_8f62 {
  strings:
    $key_8f62 = { d8 10 [2] ea 32 [2] ec 07 [2] c2 07 [2] fd 1b }

  condition:
    any of them
}