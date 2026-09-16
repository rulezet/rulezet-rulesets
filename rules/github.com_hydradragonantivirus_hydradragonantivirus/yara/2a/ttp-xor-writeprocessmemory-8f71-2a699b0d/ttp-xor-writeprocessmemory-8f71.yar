rule TTP_XOR_WriteProcessMemory_8f71 {
  strings:
    $key_8f71 = { d8 03 [2] ea 21 [2] ec 14 [2] c2 14 [2] fd 08 }

  condition:
    any of them
}