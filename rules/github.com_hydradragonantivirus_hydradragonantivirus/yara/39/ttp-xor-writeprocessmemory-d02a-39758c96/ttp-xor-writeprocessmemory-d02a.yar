rule TTP_XOR_WriteProcessMemory_d02a {
  strings:
    $key_d02a = { 87 58 [2] b5 7a [2] b3 4f [2] 9d 4f [2] a2 53 }

  condition:
    any of them
}