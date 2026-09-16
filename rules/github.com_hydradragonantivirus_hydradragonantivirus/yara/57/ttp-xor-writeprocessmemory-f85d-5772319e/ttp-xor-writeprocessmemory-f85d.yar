rule TTP_XOR_WriteProcessMemory_f85d {
  strings:
    $key_f85d = { af 2f [2] 9d 0d [2] 9b 38 [2] b5 38 [2] 8a 24 }

  condition:
    any of them
}