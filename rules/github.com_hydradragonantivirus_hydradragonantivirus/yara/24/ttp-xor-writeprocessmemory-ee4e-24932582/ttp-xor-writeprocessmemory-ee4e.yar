rule TTP_XOR_WriteProcessMemory_ee4e {
  strings:
    $key_ee4e = { b9 3c [2] 8b 1e [2] 8d 2b [2] a3 2b [2] 9c 37 }

  condition:
    any of them
}