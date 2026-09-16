rule TTP_XOR_WriteProcessMemory_2eb8 {
  strings:
    $key_2eb8 = { 79 ca [2] 4b e8 [2] 4d dd [2] 63 dd [2] 5c c1 }

  condition:
    any of them
}