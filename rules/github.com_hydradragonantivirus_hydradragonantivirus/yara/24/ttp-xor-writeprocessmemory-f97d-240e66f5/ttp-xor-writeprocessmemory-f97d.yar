rule TTP_XOR_WriteProcessMemory_f97d {
  strings:
    $key_f97d = { ae 0f [2] 9c 2d [2] 9a 18 [2] b4 18 [2] 8b 04 }

  condition:
    any of them
}