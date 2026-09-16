rule TTP_XOR_WriteProcessMemory_ebdb {
  strings:
    $key_ebdb = { bc a9 [2] 8e 8b [2] 88 be [2] a6 be [2] 99 a2 }

  condition:
    any of them
}