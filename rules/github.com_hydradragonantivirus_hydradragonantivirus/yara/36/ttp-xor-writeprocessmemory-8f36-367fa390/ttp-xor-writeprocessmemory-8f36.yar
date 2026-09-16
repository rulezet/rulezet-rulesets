rule TTP_XOR_WriteProcessMemory_8f36 {
  strings:
    $key_8f36 = { d8 44 [2] ea 66 [2] ec 53 [2] c2 53 [2] fd 4f }

  condition:
    any of them
}