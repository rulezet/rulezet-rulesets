rule TTP_XOR_WriteProcessMemory_daab {
  strings:
    $key_daab = { 8d d9 [2] bf fb [2] b9 ce [2] 97 ce [2] a8 d2 }

  condition:
    any of them
}