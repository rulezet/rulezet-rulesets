rule TTP_XOR_WriteProcessMemory_55fe {
  strings:
    $key_55fe = { 02 8c [2] 30 ae [2] 36 9b [2] 18 9b [2] 27 87 }

  condition:
    any of them
}