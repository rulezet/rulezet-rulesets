rule TTP_XOR_WriteProcessMemory_7efe {
  strings:
    $key_7efe = { 29 8c [2] 1b ae [2] 1d 9b [2] 33 9b [2] 0c 87 }

  condition:
    any of them
}