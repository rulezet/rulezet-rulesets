rule TTP_XOR_WriteProcessMemory_f92a {
  strings:
    $key_f92a = { ae 58 [2] 9c 7a [2] 9a 4f [2] b4 4f [2] 8b 53 }

  condition:
    any of them
}