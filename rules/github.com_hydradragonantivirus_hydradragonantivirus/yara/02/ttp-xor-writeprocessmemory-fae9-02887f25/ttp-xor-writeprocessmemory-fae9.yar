rule TTP_XOR_WriteProcessMemory_fae9 {
  strings:
    $key_fae9 = { ad 9b [2] 9f b9 [2] 99 8c [2] b7 8c [2] 88 90 }

  condition:
    any of them
}