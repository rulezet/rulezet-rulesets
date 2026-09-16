rule TTP_XOR_WriteProcessMemory_081e {
  strings:
    $key_081e = { 5f 6c [2] 6d 4e [2] 6b 7b [2] 45 7b [2] 7a 67 }

  condition:
    any of them
}