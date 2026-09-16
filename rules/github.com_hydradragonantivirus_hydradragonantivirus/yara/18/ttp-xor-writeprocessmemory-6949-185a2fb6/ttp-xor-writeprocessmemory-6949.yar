rule TTP_XOR_WriteProcessMemory_6949 {
  strings:
    $key_6949 = { 3e 3b [2] 0c 19 [2] 0a 2c [2] 24 2c [2] 1b 30 }

  condition:
    any of them
}