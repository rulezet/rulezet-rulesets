rule TTP_XOR_WriteProcessMemory_1efe {
  strings:
    $key_1efe = { 49 8c [2] 7b ae [2] 7d 9b [2] 53 9b [2] 6c 87 }

  condition:
    any of them
}