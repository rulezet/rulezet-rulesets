rule TTP_XOR_WriteProcessMemory_eadb {
  strings:
    $key_eadb = { bd a9 [2] 8f 8b [2] 89 be [2] a7 be [2] 98 a2 }

  condition:
    any of them
}