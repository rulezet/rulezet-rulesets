rule TTP_XOR_WriteProcessMemory_6cfe {
  strings:
    $key_6cfe = { 3b 8c [2] 09 ae [2] 0f 9b [2] 21 9b [2] 1e 87 }

  condition:
    any of them
}