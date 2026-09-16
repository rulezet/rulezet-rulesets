rule TTP_XOR_WriteProcessMemory_986c {
  strings:
    $key_986c = { cf 1e [2] fd 3c [2] fb 09 [2] d5 09 [2] ea 15 }

  condition:
    any of them
}