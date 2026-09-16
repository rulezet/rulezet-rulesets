rule TTP_XOR_WriteProcessMemory_6efe {
  strings:
    $key_6efe = { 39 8c [2] 0b ae [2] 0d 9b [2] 23 9b [2] 1c 87 }

  condition:
    any of them
}