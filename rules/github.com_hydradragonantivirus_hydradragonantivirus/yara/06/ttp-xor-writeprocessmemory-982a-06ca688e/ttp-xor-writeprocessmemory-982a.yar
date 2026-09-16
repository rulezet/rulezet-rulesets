rule TTP_XOR_WriteProcessMemory_982a {
  strings:
    $key_982a = { cf 58 [2] fd 7a [2] fb 4f [2] d5 4f [2] ea 53 }

  condition:
    any of them
}