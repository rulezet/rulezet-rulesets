rule TTP_XOR_WriteProcessMemory_3eec {
  strings:
    $key_3eec = { 69 9e [2] 5b bc [2] 5d 89 [2] 73 89 [2] 4c 95 }

  condition:
    any of them
}