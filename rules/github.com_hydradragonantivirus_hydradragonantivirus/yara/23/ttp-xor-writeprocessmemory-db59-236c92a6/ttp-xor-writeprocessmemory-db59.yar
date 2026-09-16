rule TTP_XOR_WriteProcessMemory_db59 {
  strings:
    $key_db59 = { 8c 2b [2] be 09 [2] b8 3c [2] 96 3c [2] a9 20 }

  condition:
    any of them
}