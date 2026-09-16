rule TTP_XOR_WriteProcessMemory_eb19 {
  strings:
    $key_eb19 = { bc 6b [2] 8e 49 [2] 88 7c [2] a6 7c [2] 99 60 }

  condition:
    any of them
}