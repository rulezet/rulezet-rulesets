rule TTP_XOR_WriteProcessMemory_8ff7 {
  strings:
    $key_8ff7 = { d8 85 [2] ea a7 [2] ec 92 [2] c2 92 [2] fd 8e }

  condition:
    any of them
}