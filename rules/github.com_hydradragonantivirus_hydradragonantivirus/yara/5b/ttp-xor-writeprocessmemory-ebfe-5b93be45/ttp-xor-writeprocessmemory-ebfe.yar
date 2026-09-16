rule TTP_XOR_WriteProcessMemory_ebfe {
  strings:
    $key_ebfe = { bc 8c [2] 8e ae [2] 88 9b [2] a6 9b [2] 99 87 }

  condition:
    any of them
}