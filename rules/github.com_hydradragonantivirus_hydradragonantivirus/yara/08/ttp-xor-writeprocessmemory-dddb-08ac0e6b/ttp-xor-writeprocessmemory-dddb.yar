rule TTP_XOR_WriteProcessMemory_dddb {
  strings:
    $key_dddb = { 8a a9 [2] b8 8b [2] be be [2] 90 be [2] af a2 }

  condition:
    any of them
}