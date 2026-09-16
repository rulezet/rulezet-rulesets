rule TTP_XOR_WriteProcessMemory_ebfd {
  strings:
    $key_ebfd = { bc 8f [2] 8e ad [2] 88 98 [2] a6 98 [2] 99 84 }

  condition:
    any of them
}