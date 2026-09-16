rule TTP_XOR_WriteProcessMemory_dbcd {
  strings:
    $key_dbcd = { 8c bf [2] be 9d [2] b8 a8 [2] 96 a8 [2] a9 b4 }

  condition:
    any of them
}