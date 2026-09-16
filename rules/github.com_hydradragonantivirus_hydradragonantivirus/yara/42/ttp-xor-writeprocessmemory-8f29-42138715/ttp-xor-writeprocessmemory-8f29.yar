rule TTP_XOR_WriteProcessMemory_8f29 {
  strings:
    $key_8f29 = { d8 5b [2] ea 79 [2] ec 4c [2] c2 4c [2] fd 50 }

  condition:
    any of them
}