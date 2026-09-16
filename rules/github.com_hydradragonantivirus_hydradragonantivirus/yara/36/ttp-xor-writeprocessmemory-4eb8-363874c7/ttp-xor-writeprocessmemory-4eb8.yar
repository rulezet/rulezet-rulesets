rule TTP_XOR_WriteProcessMemory_4eb8 {
  strings:
    $key_4eb8 = { 19 ca [2] 2b e8 [2] 2d dd [2] 03 dd [2] 3c c1 }

  condition:
    any of them
}