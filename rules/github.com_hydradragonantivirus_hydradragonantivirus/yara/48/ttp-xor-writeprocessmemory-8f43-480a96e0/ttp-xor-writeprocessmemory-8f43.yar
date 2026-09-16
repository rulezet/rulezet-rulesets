rule TTP_XOR_WriteProcessMemory_8f43 {
  strings:
    $key_8f43 = { d8 31 [2] ea 13 [2] ec 26 [2] c2 26 [2] fd 3a }

  condition:
    any of them
}