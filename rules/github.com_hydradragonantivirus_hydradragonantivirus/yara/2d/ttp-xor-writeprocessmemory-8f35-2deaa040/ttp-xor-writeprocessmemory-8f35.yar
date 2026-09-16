rule TTP_XOR_WriteProcessMemory_8f35 {
  strings:
    $key_8f35 = { d8 47 [2] ea 65 [2] ec 50 [2] c2 50 [2] fd 4c }

  condition:
    any of them
}