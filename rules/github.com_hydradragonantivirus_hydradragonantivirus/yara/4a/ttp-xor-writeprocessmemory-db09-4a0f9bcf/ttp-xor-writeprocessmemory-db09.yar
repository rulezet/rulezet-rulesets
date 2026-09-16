rule TTP_XOR_WriteProcessMemory_db09 {
  strings:
    $key_db09 = { 8c 7b [2] be 59 [2] b8 6c [2] 96 6c [2] a9 70 }

  condition:
    any of them
}