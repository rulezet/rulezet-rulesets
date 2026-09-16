rule TTP_XOR_WriteProcessMemory_8fe4 {
  strings:
    $key_8fe4 = { d8 96 [2] ea b4 [2] ec 81 [2] c2 81 [2] fd 9d }

  condition:
    any of them
}