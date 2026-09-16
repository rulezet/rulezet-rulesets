rule TTP_XOR_WriteProcessMemory_cabb {
  strings:
    $key_cabb = { 9d c9 [2] af eb [2] a9 de [2] 87 de [2] b8 c2 }

  condition:
    any of them
}