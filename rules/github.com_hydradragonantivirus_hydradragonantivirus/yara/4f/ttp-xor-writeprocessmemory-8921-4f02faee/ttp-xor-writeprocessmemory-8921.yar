rule TTP_XOR_WriteProcessMemory_8921 {
  strings:
    $key_8921 = { de 53 [2] ec 71 [2] ea 44 [2] c4 44 [2] fb 58 }

  condition:
    any of them
}