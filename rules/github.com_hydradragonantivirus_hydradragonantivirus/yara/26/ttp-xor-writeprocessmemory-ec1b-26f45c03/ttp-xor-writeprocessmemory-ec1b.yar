rule TTP_XOR_WriteProcessMemory_ec1b {
  strings:
    $key_ec1b = { bb 69 [2] 89 4b [2] 8f 7e [2] a1 7e [2] 9e 62 }

  condition:
    any of them
}