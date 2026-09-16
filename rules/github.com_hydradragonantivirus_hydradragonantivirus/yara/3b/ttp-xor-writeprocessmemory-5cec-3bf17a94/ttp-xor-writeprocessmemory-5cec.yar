rule TTP_XOR_WriteProcessMemory_5cec {
  strings:
    $key_5cec = { 0b 9e [2] 39 bc [2] 3f 89 [2] 11 89 [2] 2e 95 }

  condition:
    any of them
}