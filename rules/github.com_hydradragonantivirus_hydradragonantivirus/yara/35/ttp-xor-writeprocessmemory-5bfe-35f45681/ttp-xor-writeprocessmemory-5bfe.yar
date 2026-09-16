rule TTP_XOR_WriteProcessMemory_5bfe {
  strings:
    $key_5bfe = { 0c 8c [2] 3e ae [2] 38 9b [2] 16 9b [2] 29 87 }

  condition:
    any of them
}