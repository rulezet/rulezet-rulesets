rule TTP_XOR_WriteProcessMemory_ee0e {
  strings:
    $key_ee0e = { b9 7c [2] 8b 5e [2] 8d 6b [2] a3 6b [2] 9c 77 }

  condition:
    any of them
}