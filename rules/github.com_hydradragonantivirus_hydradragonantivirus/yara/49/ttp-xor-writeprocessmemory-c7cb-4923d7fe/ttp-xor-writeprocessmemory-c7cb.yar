rule TTP_XOR_WriteProcessMemory_c7cb {
  strings:
    $key_c7cb = { 90 b9 [2] a2 9b [2] a4 ae [2] 8a ae [2] b5 b2 }

  condition:
    any of them
}