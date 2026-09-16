rule TTP_XOR_WriteProcessMemory_dbdf {
  strings:
    $key_dbdf = { 8c ad [2] be 8f [2] b8 ba [2] 96 ba [2] a9 a6 }

  condition:
    any of them
}