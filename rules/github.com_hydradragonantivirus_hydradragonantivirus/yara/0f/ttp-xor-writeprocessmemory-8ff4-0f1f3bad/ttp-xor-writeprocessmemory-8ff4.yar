rule TTP_XOR_WriteProcessMemory_8ff4 {
  strings:
    $key_8ff4 = { d8 86 [2] ea a4 [2] ec 91 [2] c2 91 [2] fd 8d }

  condition:
    any of them
}