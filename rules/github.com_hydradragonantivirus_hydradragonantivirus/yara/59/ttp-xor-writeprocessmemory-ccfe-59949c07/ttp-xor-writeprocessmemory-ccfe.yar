rule TTP_XOR_WriteProcessMemory_ccfe {
  strings:
    $key_ccfe = { 9b 8c [2] a9 ae [2] af 9b [2] 81 9b [2] be 87 }

  condition:
    any of them
}