rule TTP_XOR_WriteProcessMemory_2cec {
  strings:
    $key_2cec = { 7b 9e [2] 49 bc [2] 4f 89 [2] 61 89 [2] 5e 95 }

  condition:
    any of them
}