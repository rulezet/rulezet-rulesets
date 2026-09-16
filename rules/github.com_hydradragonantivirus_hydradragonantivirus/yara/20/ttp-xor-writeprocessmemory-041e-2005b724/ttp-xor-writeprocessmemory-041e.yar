rule TTP_XOR_WriteProcessMemory_041e {
  strings:
    $key_041e = { 53 6c [2] 61 4e [2] 67 7b [2] 49 7b [2] 76 67 }

  condition:
    any of them
}