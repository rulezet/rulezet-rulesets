rule TTP_XOR_WriteProcessMemory_ebac {
  strings:
    $key_ebac = { bc de [2] 8e fc [2] 88 c9 [2] a6 c9 [2] 99 d5 }

  condition:
    any of them
}