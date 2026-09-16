rule TTP_XOR_WriteProcessMemory_ecea {
  strings:
    $key_ecea = { bb 98 [2] 89 ba [2] 8f 8f [2] a1 8f [2] 9e 93 }

  condition:
    any of them
}