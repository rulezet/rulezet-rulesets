rule TTP_XOR_WriteProcessMemory_8f6f {
  strings:
    $key_8f6f = { d8 1d [2] ea 3f [2] ec 0a [2] c2 0a [2] fd 16 }

  condition:
    any of them
}