rule TTP_XOR_WriteProcessMemory_89ef {
  strings:
    $key_89ef = { de 9d [2] ec bf [2] ea 8a [2] c4 8a [2] fb 96 }

  condition:
    any of them
}