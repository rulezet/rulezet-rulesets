rule TTP_XOR_WriteProcessMemory_893d {
  strings:
    $key_893d = { de 4f [2] ec 6d [2] ea 58 [2] c4 58 [2] fb 44 }

  condition:
    any of them
}