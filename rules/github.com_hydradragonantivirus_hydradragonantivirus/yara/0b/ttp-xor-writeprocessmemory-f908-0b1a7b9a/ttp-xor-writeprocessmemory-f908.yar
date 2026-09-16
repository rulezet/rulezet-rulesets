rule TTP_XOR_WriteProcessMemory_f908 {
  strings:
    $key_f908 = { ae 7a [2] 9c 58 [2] 9a 6d [2] b4 6d [2] 8b 71 }

  condition:
    any of them
}