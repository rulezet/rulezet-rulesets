rule TTP_XOR_WriteProcessMemory_db01 {
  strings:
    $key_db01 = { 8c 73 [2] be 51 [2] b8 64 [2] 96 64 [2] a9 78 }

  condition:
    any of them
}