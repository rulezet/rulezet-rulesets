rule TTP_XOR_WriteProcessMemory_ee7b {
  strings:
    $key_ee7b = { b9 09 [2] 8b 2b [2] 8d 1e [2] a3 1e [2] 9c 02 }

  condition:
    any of them
}