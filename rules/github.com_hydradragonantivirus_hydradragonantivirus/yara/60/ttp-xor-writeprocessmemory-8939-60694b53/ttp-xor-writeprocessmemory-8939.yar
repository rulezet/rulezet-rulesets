rule TTP_XOR_WriteProcessMemory_8939 {
  strings:
    $key_8939 = { de 4b [2] ec 69 [2] ea 5c [2] c4 5c [2] fb 40 }

  condition:
    any of them
}