rule TTP_XOR_WriteProcessMemory_ebb8 {
  strings:
    $key_ebb8 = { bc ca [2] 8e e8 [2] 88 dd [2] a6 dd [2] 99 c1 }

  condition:
    any of them
}