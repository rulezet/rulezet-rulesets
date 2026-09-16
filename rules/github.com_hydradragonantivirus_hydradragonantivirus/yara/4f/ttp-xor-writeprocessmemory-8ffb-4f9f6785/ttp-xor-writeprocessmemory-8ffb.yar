rule TTP_XOR_WriteProcessMemory_8ffb {
  strings:
    $key_8ffb = { d8 89 [2] ea ab [2] ec 9e [2] c2 9e [2] fd 82 }

  condition:
    any of them
}