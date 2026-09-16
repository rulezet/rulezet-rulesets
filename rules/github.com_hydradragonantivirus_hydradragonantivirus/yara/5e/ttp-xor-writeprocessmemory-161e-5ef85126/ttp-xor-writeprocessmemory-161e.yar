rule TTP_XOR_WriteProcessMemory_161e {
  strings:
    $key_161e = { 41 6c [2] 73 4e [2] 75 7b [2] 5b 7b [2] 64 67 }

  condition:
    any of them
}