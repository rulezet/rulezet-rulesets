rule TTP_XOR_WriteProcessMemory_8f6d {
  strings:
    $key_8f6d = { d8 1f [2] ea 3d [2] ec 08 [2] c2 08 [2] fd 14 }

  condition:
    any of them
}