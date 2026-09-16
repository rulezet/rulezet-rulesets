rule TTP_XOR_WriteProcessMemory_987f {
  strings:
    $key_987f = { cf 0d [2] fd 2f [2] fb 1a [2] d5 1a [2] ea 06 }

  condition:
    any of them
}