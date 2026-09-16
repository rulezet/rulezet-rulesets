rule TTP_XOR_WriteProcessMemory_c1fe {
  strings:
    $key_c1fe = { 96 8c [2] a4 ae [2] a2 9b [2] 8c 9b [2] b3 87 }

  condition:
    any of them
}