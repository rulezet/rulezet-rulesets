rule TTP_XOR_WriteProcessMemory_8914 {
  strings:
    $key_8914 = { de 66 [2] ec 44 [2] ea 71 [2] c4 71 [2] fb 6d }

  condition:
    any of them
}