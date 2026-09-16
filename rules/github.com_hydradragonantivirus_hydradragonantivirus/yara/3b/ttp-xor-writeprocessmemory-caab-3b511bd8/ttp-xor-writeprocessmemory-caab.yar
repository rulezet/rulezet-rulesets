rule TTP_XOR_WriteProcessMemory_caab {
  strings:
    $key_caab = { 9d d9 [2] af fb [2] a9 ce [2] 87 ce [2] b8 d2 }

  condition:
    any of them
}