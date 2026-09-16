rule TTP_XOR_WriteProcessMemory_0eec {
  strings:
    $key_0eec = { 59 9e [2] 6b bc [2] 6d 89 [2] 43 89 [2] 7c 95 }

  condition:
    any of them
}