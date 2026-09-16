rule TTP_XOR_WriteProcessMemory_ef7e {
  strings:
    $key_ef7e = { b8 0c [2] 8a 2e [2] 8c 1b [2] a2 1b [2] 9d 07 }

  condition:
    any of them
}