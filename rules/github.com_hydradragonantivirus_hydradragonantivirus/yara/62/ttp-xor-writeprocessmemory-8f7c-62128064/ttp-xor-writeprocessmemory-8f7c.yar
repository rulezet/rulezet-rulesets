rule TTP_XOR_WriteProcessMemory_8f7c {
  strings:
    $key_8f7c = { d8 0e [2] ea 2c [2] ec 19 [2] c2 19 [2] fd 05 }

  condition:
    any of them
}