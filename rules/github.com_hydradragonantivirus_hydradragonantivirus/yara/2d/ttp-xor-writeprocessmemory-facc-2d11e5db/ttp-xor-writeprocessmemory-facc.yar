rule TTP_XOR_WriteProcessMemory_facc {
  strings:
    $key_facc = { ad be [2] 9f 9c [2] 99 a9 [2] b7 a9 [2] 88 b5 }

  condition:
    any of them
}