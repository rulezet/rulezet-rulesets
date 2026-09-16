rule TTP_XOR_WriteProcessMemory_0dee {
  strings:
    $key_0dee = { 5a 9c [2] 68 be [2] 6e 8b [2] 40 8b [2] 7f 97 }

  condition:
    any of them
}