rule TTP_XOR_WriteProcessMemory_2eec {
  strings:
    $key_2eec = { 79 9e [2] 4b bc [2] 4d 89 [2] 63 89 [2] 5c 95 }

  condition:
    any of them
}