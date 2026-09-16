rule TTP_XOR_WriteProcessMemory_ffdc {
  strings:
    $key_ffdc = { a8 ae [2] 9a 8c [2] 9c b9 [2] b2 b9 [2] 8d a5 }

  condition:
    any of them
}