rule TTP_XOR_WriteProcessMemory_d03a {
  strings:
    $key_d03a = { 87 48 [2] b5 6a [2] b3 5f [2] 9d 5f [2] a2 43 }

  condition:
    any of them
}