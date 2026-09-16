rule TTP_XOR_WriteProcessMemory_f94d {
  strings:
    $key_f94d = { ae 3f [2] 9c 1d [2] 9a 28 [2] b4 28 [2] 8b 34 }

  condition:
    any of them
}