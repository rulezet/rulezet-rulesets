rule TTP_XOR_WriteProcessMemory_e90a {
  strings:
    $key_e90a = { be 78 [2] 8c 5a [2] 8a 6f [2] a4 6f [2] 9b 73 }

  condition:
    any of them
}