rule TTP_XOR_WriteProcessMemory_8f27 {
  strings:
    $key_8f27 = { d8 55 [2] ea 77 [2] ec 42 [2] c2 42 [2] fd 5e }

  condition:
    any of them
}