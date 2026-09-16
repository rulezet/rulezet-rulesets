rule TTP_XOR_WriteProcessMemory_d58e {
  strings:
    $key_d58e = { 82 fc [2] b0 de [2] b6 eb [2] 98 eb [2] a7 f7 }

  condition:
    any of them
}