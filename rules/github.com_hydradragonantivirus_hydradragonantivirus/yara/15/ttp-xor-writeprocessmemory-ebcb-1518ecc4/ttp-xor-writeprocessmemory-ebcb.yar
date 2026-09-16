rule TTP_XOR_WriteProcessMemory_ebcb {
  strings:
    $key_ebcb = { bc b9 [2] 8e 9b [2] 88 ae [2] a6 ae [2] 99 b2 }

  condition:
    any of them
}