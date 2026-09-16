rule TTP_XOR_WriteProcessMemory_989a {
  strings:
    $key_989a = { cf e8 [2] fd ca [2] fb ff [2] d5 ff [2] ea e3 }

  condition:
    any of them
}