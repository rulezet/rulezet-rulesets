rule TTP_XOR_WriteProcessMemory_ebee {
  strings:
    $key_ebee = { bc 9c [2] 8e be [2] 88 8b [2] a6 8b [2] 99 97 }

  condition:
    any of them
}