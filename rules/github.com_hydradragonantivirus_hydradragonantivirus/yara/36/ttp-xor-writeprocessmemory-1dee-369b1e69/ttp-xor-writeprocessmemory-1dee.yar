rule TTP_XOR_WriteProcessMemory_1dee {
  strings:
    $key_1dee = { 4a 9c [2] 78 be [2] 7e 8b [2] 50 8b [2] 6f 97 }

  condition:
    any of them
}