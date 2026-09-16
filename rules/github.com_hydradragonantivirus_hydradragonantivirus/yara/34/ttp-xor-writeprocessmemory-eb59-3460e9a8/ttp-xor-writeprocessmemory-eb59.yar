rule TTP_XOR_WriteProcessMemory_eb59 {
  strings:
    $key_eb59 = { bc 2b [2] 8e 09 [2] 88 3c [2] a6 3c [2] 99 20 }

  condition:
    any of them
}