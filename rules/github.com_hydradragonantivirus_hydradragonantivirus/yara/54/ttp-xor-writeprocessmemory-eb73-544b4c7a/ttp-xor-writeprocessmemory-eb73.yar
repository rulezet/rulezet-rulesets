rule TTP_XOR_WriteProcessMemory_eb73 {
  strings:
    $key_eb73 = { bc 01 [2] 8e 23 [2] 88 16 [2] a6 16 [2] 99 0a }

  condition:
    any of them
}