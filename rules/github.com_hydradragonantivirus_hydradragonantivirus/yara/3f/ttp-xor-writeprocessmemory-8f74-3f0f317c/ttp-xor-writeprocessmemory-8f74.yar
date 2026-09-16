rule TTP_XOR_WriteProcessMemory_8f74 {
  strings:
    $key_8f74 = { d8 06 [2] ea 24 [2] ec 11 [2] c2 11 [2] fd 0d }

  condition:
    any of them
}