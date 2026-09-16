rule TTP_XOR_WriteProcessMemory_5dcc {
  strings:
    $key_5dcc = { 0a be [2] 38 9c [2] 3e a9 [2] 10 a9 [2] 2f b5 }

  condition:
    any of them
}