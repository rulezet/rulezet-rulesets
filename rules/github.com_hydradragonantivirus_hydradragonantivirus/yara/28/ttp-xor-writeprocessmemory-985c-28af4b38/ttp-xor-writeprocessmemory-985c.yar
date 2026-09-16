rule TTP_XOR_WriteProcessMemory_985c {
  strings:
    $key_985c = { cf 2e [2] fd 0c [2] fb 39 [2] d5 39 [2] ea 25 }

  condition:
    any of them
}