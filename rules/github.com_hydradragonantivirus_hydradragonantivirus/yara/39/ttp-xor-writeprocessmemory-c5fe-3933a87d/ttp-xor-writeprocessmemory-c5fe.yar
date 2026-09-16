rule TTP_XOR_WriteProcessMemory_c5fe {
  strings:
    $key_c5fe = { 92 8c [2] a0 ae [2] a6 9b [2] 88 9b [2] b7 87 }

  condition:
    any of them
}