rule TTP_XOR_WriteProcessMemory_33fe {
  strings:
    $key_33fe = { 64 8c [2] 56 ae [2] 50 9b [2] 7e 9b [2] 41 87 }

  condition:
    any of them
}