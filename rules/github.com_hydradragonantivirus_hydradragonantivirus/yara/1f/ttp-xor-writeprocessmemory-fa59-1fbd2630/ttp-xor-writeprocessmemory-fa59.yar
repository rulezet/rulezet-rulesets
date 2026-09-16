rule TTP_XOR_WriteProcessMemory_fa59 {
  strings:
    $key_fa59 = { ad 2b [2] 9f 09 [2] 99 3c [2] b7 3c [2] 88 20 }

  condition:
    any of them
}