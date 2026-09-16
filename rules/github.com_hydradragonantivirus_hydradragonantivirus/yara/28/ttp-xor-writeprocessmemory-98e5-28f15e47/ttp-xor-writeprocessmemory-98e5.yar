rule TTP_XOR_WriteProcessMemory_98e5 {
  strings:
    $key_98e5 = { cf 97 [2] fd b5 [2] fb 80 [2] d5 80 [2] ea 9c }

  condition:
    any of them
}