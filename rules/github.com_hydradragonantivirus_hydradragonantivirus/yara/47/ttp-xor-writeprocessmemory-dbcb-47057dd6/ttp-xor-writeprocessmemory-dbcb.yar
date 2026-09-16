rule TTP_XOR_WriteProcessMemory_dbcb {
  strings:
    $key_dbcb = { 8c b9 [2] be 9b [2] b8 ae [2] 96 ae [2] a9 b2 }

  condition:
    any of them
}