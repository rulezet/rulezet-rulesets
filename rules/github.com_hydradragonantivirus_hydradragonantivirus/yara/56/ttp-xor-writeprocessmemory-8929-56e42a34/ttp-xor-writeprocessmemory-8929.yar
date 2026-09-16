rule TTP_XOR_WriteProcessMemory_8929 {
  strings:
    $key_8929 = { de 5b [2] ec 79 [2] ea 4c [2] c4 4c [2] fb 50 }

  condition:
    any of them
}