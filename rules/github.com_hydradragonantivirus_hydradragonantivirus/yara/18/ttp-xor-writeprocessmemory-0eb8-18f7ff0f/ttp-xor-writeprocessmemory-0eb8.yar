rule TTP_XOR_WriteProcessMemory_0eb8 {
  strings:
    $key_0eb8 = { 59 ca [2] 6b e8 [2] 6d dd [2] 43 dd [2] 7c c1 }

  condition:
    any of them
}