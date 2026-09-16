rule TTP_XOR_WriteProcessMemory_8f60 {
  strings:
    $key_8f60 = { d8 12 [2] ea 30 [2] ec 05 [2] c2 05 [2] fd 19 }

  condition:
    any of them
}