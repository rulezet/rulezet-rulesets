rule TTP_XOR_WriteProcessMemory_0dcc {
  strings:
    $key_0dcc = { 5a be [2] 68 9c [2] 6e a9 [2] 40 a9 [2] 7f b5 }

  condition:
    any of them
}