rule TTP_XOR_WriteProcessMemory_54fe {
  strings:
    $key_54fe = { 03 8c [2] 31 ae [2] 37 9b [2] 19 9b [2] 26 87 }

  condition:
    any of them
}