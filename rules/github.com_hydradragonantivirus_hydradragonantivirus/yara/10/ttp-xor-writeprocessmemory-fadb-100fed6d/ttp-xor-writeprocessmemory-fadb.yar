rule TTP_XOR_WriteProcessMemory_fadb {
  strings:
    $key_fadb = { ad a9 [2] 9f 8b [2] 99 be [2] b7 be [2] 88 a2 }

  condition:
    any of them
}