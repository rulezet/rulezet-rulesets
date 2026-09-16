rule TTP_XOR_WriteProcessMemory_1cec {
  strings:
    $key_1cec = { 4b 9e [2] 79 bc [2] 7f 89 [2] 51 89 [2] 6e 95 }

  condition:
    any of them
}