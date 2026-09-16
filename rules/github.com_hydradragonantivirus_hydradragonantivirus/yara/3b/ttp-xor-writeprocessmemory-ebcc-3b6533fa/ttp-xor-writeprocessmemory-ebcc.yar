rule TTP_XOR_WriteProcessMemory_ebcc {
  strings:
    $key_ebcc = { bc be [2] 8e 9c [2] 88 a9 [2] a6 a9 [2] 99 b5 }

  condition:
    any of them
}