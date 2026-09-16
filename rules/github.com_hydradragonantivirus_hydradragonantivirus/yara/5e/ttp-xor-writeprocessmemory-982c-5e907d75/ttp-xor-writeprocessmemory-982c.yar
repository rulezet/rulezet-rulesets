rule TTP_XOR_WriteProcessMemory_982c {
  strings:
    $key_982c = { cf 5e [2] fd 7c [2] fb 49 [2] d5 49 [2] ea 55 }

  condition:
    any of them
}