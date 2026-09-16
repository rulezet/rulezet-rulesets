rule TTP_XOR_WriteProcessMemory_893b {
  strings:
    $key_893b = { de 49 [2] ec 6b [2] ea 5e [2] c4 5e [2] fb 42 }

  condition:
    any of them
}