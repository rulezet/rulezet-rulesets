rule TTP_XOR_WriteProcessMemory_e9ef {
  strings:
    $key_e9ef = { be 9d [2] 8c bf [2] 8a 8a [2] a4 8a [2] 9b 96 }

  condition:
    any of them
}