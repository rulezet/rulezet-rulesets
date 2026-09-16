rule TTP_XOR_WriteProcessMemory_981d {
  strings:
    $key_981d = { cf 6f [2] fd 4d [2] fb 78 [2] d5 78 [2] ea 64 }

  condition:
    any of them
}