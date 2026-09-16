rule TTP_XOR_WriteProcessMemory_8f39 {
  strings:
    $key_8f39 = { d8 4b [2] ea 69 [2] ec 5c [2] c2 5c [2] fd 40 }

  condition:
    any of them
}