rule TTP_XOR_WriteProcessMemory_fefe {
  strings:
    $key_fefe = { a9 8c [2] 9b ae [2] 9d 9b [2] b3 9b [2] 8c 87 }

  condition:
    any of them
}