rule TTP_XOR_WriteProcessMemory_8f75 {
  strings:
    $key_8f75 = { d8 07 [2] ea 25 [2] ec 10 [2] c2 10 [2] fd 0c }

  condition:
    any of them
}