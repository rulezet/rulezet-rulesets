rule TTP_XOR_WriteProcessMemory_fa19 {
  strings:
    $key_fa19 = { ad 6b [2] 9f 49 [2] 99 7c [2] b7 7c [2] 88 60 }

  condition:
    any of them
}