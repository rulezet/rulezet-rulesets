rule TTP_XOR_WriteProcessMemory_d00a {
  strings:
    $key_d00a = { 87 78 [2] b5 5a [2] b3 6f [2] 9d 6f [2] a2 73 }

  condition:
    any of them
}