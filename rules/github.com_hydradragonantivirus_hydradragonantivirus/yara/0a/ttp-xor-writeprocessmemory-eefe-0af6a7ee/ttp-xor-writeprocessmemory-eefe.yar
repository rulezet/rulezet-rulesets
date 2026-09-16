rule TTP_XOR_WriteProcessMemory_eefe {
  strings:
    $key_eefe = { b9 8c [2] 8b ae [2] 8d 9b [2] a3 9b [2] 9c 87 }

  condition:
    any of them
}