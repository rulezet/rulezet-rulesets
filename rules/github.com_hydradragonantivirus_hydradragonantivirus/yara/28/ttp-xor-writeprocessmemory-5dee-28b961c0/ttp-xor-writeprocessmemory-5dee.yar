rule TTP_XOR_WriteProcessMemory_5dee {
  strings:
    $key_5dee = { 0a 9c [2] 38 be [2] 3e 8b [2] 10 8b [2] 2f 97 }

  condition:
    any of them
}