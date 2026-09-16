rule TTP_XOR_WriteProcessMemory_8fe2 {
  strings:
    $key_8fe2 = { d8 90 [2] ea b2 [2] ec 87 [2] c2 87 [2] fd 9b }

  condition:
    any of them
}