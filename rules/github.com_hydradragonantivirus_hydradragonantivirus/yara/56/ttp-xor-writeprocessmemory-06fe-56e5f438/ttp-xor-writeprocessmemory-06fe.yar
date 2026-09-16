rule TTP_XOR_WriteProcessMemory_06fe {
  strings:
    $key_06fe = { 51 8c [2] 63 ae [2] 65 9b [2] 4b 9b [2] 74 87 }

  condition:
    any of them
}