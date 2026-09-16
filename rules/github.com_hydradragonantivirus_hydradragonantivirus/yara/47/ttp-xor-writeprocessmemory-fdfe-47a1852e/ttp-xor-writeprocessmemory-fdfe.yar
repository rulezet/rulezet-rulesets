rule TTP_XOR_WriteProcessMemory_fdfe {
  strings:
    $key_fdfe = { aa 8c [2] 98 ae [2] 9e 9b [2] b0 9b [2] 8f 87 }

  condition:
    any of them
}