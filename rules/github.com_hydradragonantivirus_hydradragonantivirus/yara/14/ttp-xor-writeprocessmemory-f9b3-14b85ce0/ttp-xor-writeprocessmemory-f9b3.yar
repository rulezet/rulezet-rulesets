rule TTP_XOR_WriteProcessMemory_f9b3 {
  strings:
    $key_f9b3 = { ae c1 [2] 9c e3 [2] 9a d6 [2] b4 d6 [2] 8b ca }

  condition:
    any of them
}