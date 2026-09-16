rule TTP_XOR_WriteProcessMemory_2cfe {
  strings:
    $key_2cfe = { 7b 8c [2] 49 ae [2] 4f 9b [2] 61 9b [2] 5e 87 }

  condition:
    any of them
}