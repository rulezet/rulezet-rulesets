rule TTP_XOR_WriteProcessMemory_898c {
  strings:
    $key_898c = { de fe [2] ec dc [2] ea e9 [2] c4 e9 [2] fb f5 }

  condition:
    any of them
}