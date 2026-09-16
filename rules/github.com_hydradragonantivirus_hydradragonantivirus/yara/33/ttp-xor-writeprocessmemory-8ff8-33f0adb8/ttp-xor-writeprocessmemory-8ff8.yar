rule TTP_XOR_WriteProcessMemory_8ff8 {
  strings:
    $key_8ff8 = { d8 8a [2] ea a8 [2] ec 9d [2] c2 9d [2] fd 81 }

  condition:
    any of them
}