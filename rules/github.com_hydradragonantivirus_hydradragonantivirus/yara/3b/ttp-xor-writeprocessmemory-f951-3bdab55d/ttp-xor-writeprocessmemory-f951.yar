rule TTP_XOR_WriteProcessMemory_f951 {
  strings:
    $key_f951 = { ae 23 [2] 9c 01 [2] 9a 34 [2] b4 34 [2] 8b 28 }

  condition:
    any of them
}