rule TTP_XOR_WriteProcessMemory_983a {
  strings:
    $key_983a = { cf 48 [2] fd 6a [2] fb 5f [2] d5 5f [2] ea 43 }

  condition:
    any of them
}