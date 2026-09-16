rule TTP_XOR_WriteProcessMemory_8f3c {
  strings:
    $key_8f3c = { d8 4e [2] ea 6c [2] ec 59 [2] c2 59 [2] fd 45 }

  condition:
    any of them
}