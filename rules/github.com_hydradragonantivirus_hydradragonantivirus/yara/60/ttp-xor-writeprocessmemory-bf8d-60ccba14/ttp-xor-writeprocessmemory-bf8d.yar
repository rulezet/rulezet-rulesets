rule TTP_XOR_WriteProcessMemory_bf8d {
  strings:
    $key_bf8d = { e8 ff [2] da dd [2] dc e8 [2] f2 e8 [2] cd f4 }

  condition:
    any of them
}