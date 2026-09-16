rule TTP_XOR_WriteProcessMemory_fdbb {
  strings:
    $key_fdbb = { aa c9 [2] 98 eb [2] 9e de [2] b0 de [2] 8f c2 }

  condition:
    any of them
}