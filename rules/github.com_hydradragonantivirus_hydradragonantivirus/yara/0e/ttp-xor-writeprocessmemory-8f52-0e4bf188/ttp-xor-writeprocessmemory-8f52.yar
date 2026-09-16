rule TTP_XOR_WriteProcessMemory_8f52 {
  strings:
    $key_8f52 = { d8 20 [2] ea 02 [2] ec 37 [2] c2 37 [2] fd 2b }

  condition:
    any of them
}