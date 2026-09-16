rule TTP_XOR_WriteProcessMemory_894b {
  strings:
    $key_894b = { de 39 [2] ec 1b [2] ea 2e [2] c4 2e [2] fb 32 }

  condition:
    any of them
}