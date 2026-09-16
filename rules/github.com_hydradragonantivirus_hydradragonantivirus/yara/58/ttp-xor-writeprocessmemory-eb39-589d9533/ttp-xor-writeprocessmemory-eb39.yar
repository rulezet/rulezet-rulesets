rule TTP_XOR_WriteProcessMemory_eb39 {
  strings:
    $key_eb39 = { bc 4b [2] 8e 69 [2] 88 5c [2] a6 5c [2] 99 40 }

  condition:
    any of them
}