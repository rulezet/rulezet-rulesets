rule TTP_XOR_WriteProcessMemory_893c {
  strings:
    $key_893c = { de 4e [2] ec 6c [2] ea 59 [2] c4 59 [2] fb 45 }

  condition:
    any of them
}