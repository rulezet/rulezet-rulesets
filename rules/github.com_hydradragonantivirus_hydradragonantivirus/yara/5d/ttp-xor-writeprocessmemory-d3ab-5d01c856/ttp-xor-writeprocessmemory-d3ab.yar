rule TTP_XOR_WriteProcessMemory_d3ab {
  strings:
    $key_d3ab = { 84 d9 [2] b6 fb [2] b0 ce [2] 9e ce [2] a1 d2 }

  condition:
    any of them
}