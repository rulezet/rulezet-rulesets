rule TTP_XOR_WriteProcessMemory_dbca {
  strings:
    $key_dbca = { 8c b8 [2] be 9a [2] b8 af [2] 96 af [2] a9 b3 }

  condition:
    any of them
}