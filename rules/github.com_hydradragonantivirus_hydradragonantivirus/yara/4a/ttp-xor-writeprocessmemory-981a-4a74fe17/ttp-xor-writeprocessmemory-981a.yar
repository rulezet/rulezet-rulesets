rule TTP_XOR_WriteProcessMemory_981a {
  strings:
    $key_981a = { cf 68 [2] fd 4a [2] fb 7f [2] d5 7f [2] ea 63 }

  condition:
    any of them
}