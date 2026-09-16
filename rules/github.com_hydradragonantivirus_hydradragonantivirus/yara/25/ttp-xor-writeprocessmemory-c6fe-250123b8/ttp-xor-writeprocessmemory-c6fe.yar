rule TTP_XOR_WriteProcessMemory_c6fe {
  strings:
    $key_c6fe = { 91 8c [2] a3 ae [2] a5 9b [2] 8b 9b [2] b4 87 }

  condition:
    any of them
}