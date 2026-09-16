rule TTP_XOR_WriteProcessMemory_8996 {
  strings:
    $key_8996 = { de e4 [2] ec c6 [2] ea f3 [2] c4 f3 [2] fb ef }

  condition:
    any of them
}