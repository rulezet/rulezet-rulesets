rule TTP_XOR_WriteProcessMemory_8f19 {
  strings:
    $key_8f19 = { d8 6b [2] ea 49 [2] ec 7c [2] c2 7c [2] fd 60 }

  condition:
    any of them
}