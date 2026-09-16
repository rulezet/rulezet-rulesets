rule TTP_XOR_WriteProcessMemory_ccdb {
  strings:
    $key_ccdb = { 9b a9 [2] a9 8b [2] af be [2] 81 be [2] be a2 }

  condition:
    any of them
}