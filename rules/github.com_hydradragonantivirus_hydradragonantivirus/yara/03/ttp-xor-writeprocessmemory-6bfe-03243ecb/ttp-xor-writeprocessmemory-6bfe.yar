rule TTP_XOR_WriteProcessMemory_6bfe {
  strings:
    $key_6bfe = { 3c 8c [2] 0e ae [2] 08 9b [2] 26 9b [2] 19 87 }

  condition:
    any of them
}