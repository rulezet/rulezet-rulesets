rule TTP_XOR_WriteProcessMemory_8992 {
  strings:
    $key_8992 = { de e0 [2] ec c2 [2] ea f7 [2] c4 f7 [2] fb eb }

  condition:
    any of them
}