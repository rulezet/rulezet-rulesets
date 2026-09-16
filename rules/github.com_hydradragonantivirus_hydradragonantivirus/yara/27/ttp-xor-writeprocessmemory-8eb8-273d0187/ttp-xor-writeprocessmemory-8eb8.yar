rule TTP_XOR_WriteProcessMemory_8eb8 {
  strings:
    $key_8eb8 = { d9 ca [2] eb e8 [2] ed dd [2] c3 dd [2] fc c1 }

  condition:
    any of them
}