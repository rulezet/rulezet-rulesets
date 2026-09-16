rule TTP_XOR_WriteProcessMemory_8fe3 {
  strings:
    $key_8fe3 = { d8 91 [2] ea b3 [2] ec 86 [2] c2 86 [2] fd 9a }

  condition:
    any of them
}