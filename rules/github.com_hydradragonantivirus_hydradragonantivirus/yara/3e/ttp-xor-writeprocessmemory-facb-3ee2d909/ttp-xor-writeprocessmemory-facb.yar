rule TTP_XOR_WriteProcessMemory_facb {
  strings:
    $key_facb = { ad b9 [2] 9f 9b [2] 99 ae [2] b7 ae [2] 88 b2 }

  condition:
    any of them
}