rule TTP_XOR_WriteProcessMemory_12fe {
  strings:
    $key_12fe = { 45 8c [2] 77 ae [2] 71 9b [2] 5f 9b [2] 60 87 }

  condition:
    any of them
}