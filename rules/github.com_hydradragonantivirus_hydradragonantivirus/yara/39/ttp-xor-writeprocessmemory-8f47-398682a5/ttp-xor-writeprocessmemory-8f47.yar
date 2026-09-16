rule TTP_XOR_WriteProcessMemory_8f47 {
  strings:
    $key_8f47 = { d8 35 [2] ea 17 [2] ec 22 [2] c2 22 [2] fd 3e }

  condition:
    any of them
}