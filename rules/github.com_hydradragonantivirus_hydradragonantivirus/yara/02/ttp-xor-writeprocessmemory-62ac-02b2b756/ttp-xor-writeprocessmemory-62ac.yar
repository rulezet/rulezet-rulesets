rule TTP_XOR_WriteProcessMemory_62ac {
  strings:
    $key_62ac = { 35 de [2] 07 fc [2] 01 c9 [2] 2f c9 [2] 10 d5 }

  condition:
    any of them
}