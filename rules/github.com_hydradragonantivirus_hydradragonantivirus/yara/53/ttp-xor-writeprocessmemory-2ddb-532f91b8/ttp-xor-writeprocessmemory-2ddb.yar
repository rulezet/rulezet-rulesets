rule TTP_XOR_WriteProcessMemory_2ddb {
  strings:
    $key_2ddb = { 7a a9 [2] 48 8b [2] 4e be [2] 60 be [2] 5f a2 }

  condition:
    any of them
}