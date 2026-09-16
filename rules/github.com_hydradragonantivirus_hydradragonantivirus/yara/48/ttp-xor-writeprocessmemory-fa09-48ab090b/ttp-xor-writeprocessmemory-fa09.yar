rule TTP_XOR_WriteProcessMemory_fa09 {
  strings:
    $key_fa09 = { ad 7b [2] 9f 59 [2] 99 6c [2] b7 6c [2] 88 70 }

  condition:
    any of them
}