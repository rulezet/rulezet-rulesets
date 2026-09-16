rule TTP_XOR_WriteProcessMemory_d7fe {
  strings:
    $key_d7fe = { 80 8c [2] b2 ae [2] b4 9b [2] 9a 9b [2] a5 87 }

  condition:
    any of them
}