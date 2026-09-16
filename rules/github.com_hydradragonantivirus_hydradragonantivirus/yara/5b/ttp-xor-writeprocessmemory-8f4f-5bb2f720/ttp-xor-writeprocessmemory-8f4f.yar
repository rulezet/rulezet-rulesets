rule TTP_XOR_WriteProcessMemory_8f4f {
  strings:
    $key_8f4f = { d8 3d [2] ea 1f [2] ec 2a [2] c2 2a [2] fd 36 }

  condition:
    any of them
}