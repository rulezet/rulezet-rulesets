rule TTP_XOR_WriteProcessMemory_f961 {
  strings:
    $key_f961 = { ae 13 [2] 9c 31 [2] 9a 04 [2] b4 04 [2] 8b 18 }

  condition:
    any of them
}