rule TTP_XOR_WriteProcessMemory_2cdb {
  strings:
    $key_2cdb = { 7b a9 [2] 49 8b [2] 4f be [2] 61 be [2] 5e a2 }

  condition:
    any of them
}