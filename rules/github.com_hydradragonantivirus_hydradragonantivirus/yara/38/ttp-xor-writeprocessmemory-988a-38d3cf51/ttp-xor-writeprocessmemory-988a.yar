rule TTP_XOR_WriteProcessMemory_988a {
  strings:
    $key_988a = { cf f8 [2] fd da [2] fb ef [2] d5 ef [2] ea f3 }

  condition:
    any of them
}