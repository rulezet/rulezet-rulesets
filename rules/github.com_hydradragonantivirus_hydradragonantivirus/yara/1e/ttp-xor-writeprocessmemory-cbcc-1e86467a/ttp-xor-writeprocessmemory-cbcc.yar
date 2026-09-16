rule TTP_XOR_WriteProcessMemory_cbcc {
  strings:
    $key_cbcc = { 9c be [2] ae 9c [2] a8 a9 [2] 86 a9 [2] b9 b5 }

  condition:
    any of them
}