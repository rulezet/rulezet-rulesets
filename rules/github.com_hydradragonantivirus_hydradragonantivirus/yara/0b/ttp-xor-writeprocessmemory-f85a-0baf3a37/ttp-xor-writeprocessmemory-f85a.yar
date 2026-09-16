rule TTP_XOR_WriteProcessMemory_f85a {
  strings:
    $key_f85a = { af 28 [2] 9d 0a [2] 9b 3f [2] b5 3f [2] 8a 23 }

  condition:
    any of them
}