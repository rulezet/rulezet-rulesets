rule TTP_XOR_WriteProcessMemory_fae8 {
  strings:
    $key_fae8 = { ad 9a [2] 9f b8 [2] 99 8d [2] b7 8d [2] 88 91 }

  condition:
    any of them
}