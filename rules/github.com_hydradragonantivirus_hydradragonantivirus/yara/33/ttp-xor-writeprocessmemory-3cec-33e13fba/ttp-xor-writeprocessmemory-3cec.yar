rule TTP_XOR_WriteProcessMemory_3cec {
  strings:
    $key_3cec = { 6b 9e [2] 59 bc [2] 5f 89 [2] 71 89 [2] 4e 95 }

  condition:
    any of them
}