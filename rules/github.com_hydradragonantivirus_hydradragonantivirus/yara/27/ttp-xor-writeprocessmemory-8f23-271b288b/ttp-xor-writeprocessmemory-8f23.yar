rule TTP_XOR_WriteProcessMemory_8f23 {
  strings:
    $key_8f23 = { d8 51 [2] ea 73 [2] ec 46 [2] c2 46 [2] fd 5a }

  condition:
    any of them
}