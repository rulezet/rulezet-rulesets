rule TTP_XOR_WriteProcessMemory_8fbe {
  strings:
    $key_8fbe = { d8 cc [2] ea ee [2] ec db [2] c2 db [2] fd c7 }

  condition:
    any of them
}