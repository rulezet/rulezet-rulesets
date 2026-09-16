rule TTP_XOR_WriteProcessMemory_d0dc {
  strings:
    $key_d0dc = { 87 ae [2] b5 8c [2] b3 b9 [2] 9d b9 [2] a2 a5 }

  condition:
    any of them
}