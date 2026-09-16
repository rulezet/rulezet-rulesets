rule TTP_XOR_WriteProcessMemory_cdee {
  strings:
    $key_cdee = { 9a 9c [2] a8 be [2] ae 8b [2] 80 8b [2] bf 97 }

  condition:
    any of them
}