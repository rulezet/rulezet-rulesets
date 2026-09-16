rule TTP_XOR_WriteProcessMemory_f914 {
  strings:
    $key_f914 = { ae 66 [2] 9c 44 [2] 9a 71 [2] b4 71 [2] 8b 6d }

  condition:
    any of them
}