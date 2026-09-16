rule TTP_XOR_WriteProcessMemory_8908 {
  strings:
    $key_8908 = { de 7a [2] ec 58 [2] ea 6d [2] c4 6d [2] fb 71 }

  condition:
    any of them
}