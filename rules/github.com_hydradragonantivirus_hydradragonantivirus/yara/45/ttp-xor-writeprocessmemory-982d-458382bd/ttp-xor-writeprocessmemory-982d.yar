rule TTP_XOR_WriteProcessMemory_982d {
  strings:
    $key_982d = { cf 5f [2] fd 7d [2] fb 48 [2] d5 48 [2] ea 54 }

  condition:
    any of them
}