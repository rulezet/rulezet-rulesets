rule TTP_XOR_WriteProcessMemory_8f05 {
  strings:
    $key_8f05 = { d8 77 [2] ea 55 [2] ec 60 [2] c2 60 [2] fd 7c }

  condition:
    any of them
}