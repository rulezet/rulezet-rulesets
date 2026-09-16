rule TTP_XOR_WriteProcessMemory_8f45 {
  strings:
    $key_8f45 = { d8 37 [2] ea 15 [2] ec 20 [2] c2 20 [2] fd 3c }

  condition:
    any of them
}