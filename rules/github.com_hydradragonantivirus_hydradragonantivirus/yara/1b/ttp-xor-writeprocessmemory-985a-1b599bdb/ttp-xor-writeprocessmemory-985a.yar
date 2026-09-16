rule TTP_XOR_WriteProcessMemory_985a {
  strings:
    $key_985a = { cf 28 [2] fd 0a [2] fb 3f [2] d5 3f [2] ea 23 }

  condition:
    any of them
}