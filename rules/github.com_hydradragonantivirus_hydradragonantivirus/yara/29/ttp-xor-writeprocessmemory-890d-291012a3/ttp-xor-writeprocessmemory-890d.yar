rule TTP_XOR_WriteProcessMemory_890d {
  strings:
    $key_890d = { de 7f [2] ec 5d [2] ea 68 [2] c4 68 [2] fb 74 }

  condition:
    any of them
}