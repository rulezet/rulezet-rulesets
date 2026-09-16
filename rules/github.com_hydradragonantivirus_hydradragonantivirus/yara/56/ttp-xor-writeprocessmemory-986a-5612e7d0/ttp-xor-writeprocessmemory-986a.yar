rule TTP_XOR_WriteProcessMemory_986a {
  strings:
    $key_986a = { cf 18 [2] fd 3a [2] fb 0f [2] d5 0f [2] ea 13 }

  condition:
    any of them
}