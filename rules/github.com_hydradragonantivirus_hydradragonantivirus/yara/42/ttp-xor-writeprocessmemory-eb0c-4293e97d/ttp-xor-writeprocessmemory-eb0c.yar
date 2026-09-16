rule TTP_XOR_WriteProcessMemory_eb0c {
  strings:
    $key_eb0c = { bc 7e [2] 8e 5c [2] 88 69 [2] a6 69 [2] 99 75 }

  condition:
    any of them
}