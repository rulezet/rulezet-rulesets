rule TTP_XOR_WriteProcessMemory_eb23 {
  strings:
    $key_eb23 = { bc 51 [2] 8e 73 [2] 88 46 [2] a6 46 [2] 99 5a }

  condition:
    any of them
}