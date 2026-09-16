rule TTP_XOR_WriteProcessMemory_eb05 {
  strings:
    $key_eb05 = { bc 77 [2] 8e 55 [2] 88 60 [2] a6 60 [2] 99 7c }

  condition:
    any of them
}