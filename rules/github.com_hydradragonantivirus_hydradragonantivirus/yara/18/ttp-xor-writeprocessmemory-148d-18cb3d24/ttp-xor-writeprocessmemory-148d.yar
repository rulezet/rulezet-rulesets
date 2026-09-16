rule TTP_XOR_WriteProcessMemory_148d {
  strings:
    $key_148d = { 43 ff [2] 71 dd [2] 77 e8 [2] 59 e8 [2] 66 f4 }

  condition:
    any of them
}