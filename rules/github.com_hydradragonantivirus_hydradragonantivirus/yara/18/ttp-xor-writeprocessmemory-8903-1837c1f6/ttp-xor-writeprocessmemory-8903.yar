rule TTP_XOR_WriteProcessMemory_8903 {
  strings:
    $key_8903 = { de 71 [2] ec 53 [2] ea 66 [2] c4 66 [2] fb 7a }

  condition:
    any of them
}