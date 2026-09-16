rule TTP_XOR_WriteProcessMemory_8f1c {
  strings:
    $key_8f1c = { d8 6e [2] ea 4c [2] ec 79 [2] c2 79 [2] fd 65 }

  condition:
    any of them
}