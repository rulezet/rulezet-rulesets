rule TTP_XOR_WriteProcessMemory_8976 {
  strings:
    $key_8976 = { de 04 [2] ec 26 [2] ea 13 [2] c4 13 [2] fb 0f }

  condition:
    any of them
}