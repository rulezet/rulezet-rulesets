rule TTP_XOR_WriteProcessMemory_5efe {
  strings:
    $key_5efe = { 09 8c [2] 3b ae [2] 3d 9b [2] 13 9b [2] 2c 87 }

  condition:
    any of them
}