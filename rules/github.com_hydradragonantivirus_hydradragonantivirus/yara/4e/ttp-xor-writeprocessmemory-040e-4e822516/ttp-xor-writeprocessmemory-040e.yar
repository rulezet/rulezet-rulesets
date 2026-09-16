rule TTP_XOR_WriteProcessMemory_040e {
  strings:
    $key_040e = { 53 7c [2] 61 5e [2] 67 6b [2] 49 6b [2] 76 77 }

  condition:
    any of them
}