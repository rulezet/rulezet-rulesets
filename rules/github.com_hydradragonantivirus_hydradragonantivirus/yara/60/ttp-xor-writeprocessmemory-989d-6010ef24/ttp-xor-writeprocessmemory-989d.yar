rule TTP_XOR_WriteProcessMemory_989d {
  strings:
    $key_989d = { cf ef [2] fd cd [2] fb f8 [2] d5 f8 [2] ea e4 }

  condition:
    any of them
}