rule TTP_XOR_WriteProcessMemory_891b {
  strings:
    $key_891b = { de 69 [2] ec 4b [2] ea 7e [2] c4 7e [2] fb 62 }

  condition:
    any of them
}