rule TTP_XOR_WriteProcessMemory_ebfa {
  strings:
    $key_ebfa = { bc 88 [2] 8e aa [2] 88 9f [2] a6 9f [2] 99 83 }

  condition:
    any of them
}