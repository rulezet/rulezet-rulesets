rule TTP_XOR_WriteProcessMemory_c0fe {
  strings:
    $key_c0fe = { 97 8c [2] a5 ae [2] a3 9b [2] 8d 9b [2] b2 87 }

  condition:
    any of them
}