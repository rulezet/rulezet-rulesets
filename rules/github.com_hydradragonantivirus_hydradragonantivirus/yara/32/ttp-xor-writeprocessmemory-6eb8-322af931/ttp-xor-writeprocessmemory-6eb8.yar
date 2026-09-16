rule TTP_XOR_WriteProcessMemory_6eb8 {
  strings:
    $key_6eb8 = { 39 ca [2] 0b e8 [2] 0d dd [2] 23 dd [2] 1c c1 }

  condition:
    any of them
}