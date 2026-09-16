rule TTP_XOR_WriteProcessMemory_2efe {
  strings:
    $key_2efe = { 79 8c [2] 4b ae [2] 4d 9b [2] 63 9b [2] 5c 87 }

  condition:
    any of them
}