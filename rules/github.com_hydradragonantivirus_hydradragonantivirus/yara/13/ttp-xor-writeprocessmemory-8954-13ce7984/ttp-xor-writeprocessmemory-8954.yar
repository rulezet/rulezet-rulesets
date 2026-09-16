rule TTP_XOR_WriteProcessMemory_8954 {
  strings:
    $key_8954 = { de 26 [2] ec 04 [2] ea 31 [2] c4 31 [2] fb 2d }

  condition:
    any of them
}