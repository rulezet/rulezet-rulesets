rule TTP_XOR_WriteProcessMemory_cccc {
  strings:
    $key_cccc = { 9b be [2] a9 9c [2] af a9 [2] 81 a9 [2] be b5 }

  condition:
    any of them
}