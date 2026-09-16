rule TTP_XOR_WriteProcessMemory_4aee {
  strings:
    $key_4aee = { 1d 9c [2] 2f be [2] 29 8b [2] 07 8b [2] 38 97 }

  condition:
    any of them
}