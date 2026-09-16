rule TTP_XOR_WriteProcessMemory_8f7d {
  strings:
    $key_8f7d = { d8 0f [2] ea 2d [2] ec 18 [2] c2 18 [2] fd 04 }

  condition:
    any of them
}