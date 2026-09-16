rule TTP_XOR_WriteProcessMemory_ef1b {
  strings:
    $key_ef1b = { b8 69 [2] 8a 4b [2] 8c 7e [2] a2 7e [2] 9d 62 }

  condition:
    any of them
}