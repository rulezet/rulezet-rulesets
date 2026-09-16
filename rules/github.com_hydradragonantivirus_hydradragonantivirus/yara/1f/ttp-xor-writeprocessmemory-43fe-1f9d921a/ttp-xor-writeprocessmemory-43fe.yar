rule TTP_XOR_WriteProcessMemory_43fe {
  strings:
    $key_43fe = { 14 8c [2] 26 ae [2] 20 9b [2] 0e 9b [2] 31 87 }

  condition:
    any of them
}