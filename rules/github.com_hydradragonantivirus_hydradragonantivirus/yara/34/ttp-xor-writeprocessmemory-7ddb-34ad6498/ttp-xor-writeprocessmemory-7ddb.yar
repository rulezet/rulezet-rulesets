rule TTP_XOR_WriteProcessMemory_7ddb {
  strings:
    $key_7ddb = { 2a a9 [2] 18 8b [2] 1e be [2] 30 be [2] 0f a2 }

  condition:
    any of them
}