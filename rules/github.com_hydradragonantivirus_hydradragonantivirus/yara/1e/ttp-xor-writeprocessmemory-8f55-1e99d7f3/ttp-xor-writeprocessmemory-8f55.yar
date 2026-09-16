rule TTP_XOR_WriteProcessMemory_8f55 {
  strings:
    $key_8f55 = { d8 27 [2] ea 05 [2] ec 30 [2] c2 30 [2] fd 2c }

  condition:
    any of them
}