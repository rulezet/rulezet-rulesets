rule TTP_XOR_WriteProcessMemory_eb8c {
  strings:
    $key_eb8c = { bc fe [2] 8e dc [2] 88 e9 [2] a6 e9 [2] 99 f5 }

  condition:
    any of them
}