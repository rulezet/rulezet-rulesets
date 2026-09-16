rule TTP_XOR_WriteProcessMemory_733c {
  strings:
    $key_733c = { 24 4e [2] 16 6c [2] 10 59 [2] 3e 59 [2] 01 45 }

  condition:
    any of them
}