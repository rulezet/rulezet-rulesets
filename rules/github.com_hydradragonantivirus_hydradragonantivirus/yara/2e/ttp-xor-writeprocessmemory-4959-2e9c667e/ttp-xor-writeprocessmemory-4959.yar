rule TTP_XOR_WriteProcessMemory_4959 {
  strings:
    $key_4959 = { 1e 2b [2] 2c 09 [2] 2a 3c [2] 04 3c [2] 3b 20 }

  condition:
    any of them
}