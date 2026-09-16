rule TTP_XOR_WriteProcessMemory_8f70 {
  strings:
    $key_8f70 = { d8 02 [2] ea 20 [2] ec 15 [2] c2 15 [2] fd 09 }

  condition:
    any of them
}