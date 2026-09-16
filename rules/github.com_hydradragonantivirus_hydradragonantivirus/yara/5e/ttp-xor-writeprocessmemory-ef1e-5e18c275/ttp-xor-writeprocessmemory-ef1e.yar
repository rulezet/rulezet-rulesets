rule TTP_XOR_WriteProcessMemory_ef1e {
  strings:
    $key_ef1e = { b8 6c [2] 8a 4e [2] 8c 7b [2] a2 7b [2] 9d 67 }

  condition:
    any of them
}