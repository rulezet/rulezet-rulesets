rule TTP_XOR_WriteProcessMemory_8f63 {
  strings:
    $key_8f63 = { d8 11 [2] ea 33 [2] ec 06 [2] c2 06 [2] fd 1a }

  condition:
    any of them
}