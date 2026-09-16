rule TTP_XOR_WriteProcessMemory_8f01 {
  strings:
    $key_8f01 = { d8 73 [2] ea 51 [2] ec 64 [2] c2 64 [2] fd 78 }

  condition:
    any of them
}