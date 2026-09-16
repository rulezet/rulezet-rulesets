rule TTP_XOR_WriteProcessMemory_eb31 {
  strings:
    $key_eb31 = { bc 43 [2] 8e 61 [2] 88 54 [2] a6 54 [2] 99 48 }

  condition:
    any of them
}