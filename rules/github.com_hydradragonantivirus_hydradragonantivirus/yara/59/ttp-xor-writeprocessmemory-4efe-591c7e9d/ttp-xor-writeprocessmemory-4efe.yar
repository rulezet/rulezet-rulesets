rule TTP_XOR_WriteProcessMemory_4efe {
  strings:
    $key_4efe = { 19 8c [2] 2b ae [2] 2d 9b [2] 03 9b [2] 3c 87 }

  condition:
    any of them
}