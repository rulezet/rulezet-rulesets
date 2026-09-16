rule TTP_XOR_WriteProcessMemory_eb8d {
  strings:
    $key_eb8d = { bc ff [2] 8e dd [2] 88 e8 [2] a6 e8 [2] 99 f4 }

  condition:
    any of them
}