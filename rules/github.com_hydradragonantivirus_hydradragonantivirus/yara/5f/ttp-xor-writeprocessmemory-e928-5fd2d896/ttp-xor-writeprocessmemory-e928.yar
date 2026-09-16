rule TTP_XOR_WriteProcessMemory_e928 {
  strings:
    $key_e928 = { be 5a [2] 8c 78 [2] 8a 4d [2] a4 4d [2] 9b 51 }

  condition:
    any of them
}