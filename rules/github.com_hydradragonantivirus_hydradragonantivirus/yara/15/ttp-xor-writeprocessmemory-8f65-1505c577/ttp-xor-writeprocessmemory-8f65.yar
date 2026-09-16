rule TTP_XOR_WriteProcessMemory_8f65 {
  strings:
    $key_8f65 = { d8 17 [2] ea 35 [2] ec 00 [2] c2 00 [2] fd 1c }

  condition:
    any of them
}