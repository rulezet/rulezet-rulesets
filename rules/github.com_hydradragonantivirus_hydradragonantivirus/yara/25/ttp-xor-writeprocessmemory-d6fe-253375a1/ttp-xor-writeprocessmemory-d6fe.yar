rule TTP_XOR_WriteProcessMemory_d6fe {
  strings:
    $key_d6fe = { 81 8c [2] b3 ae [2] b5 9b [2] 9b 9b [2] a4 87 }

  condition:
    any of them
}