rule TTP_XOR_WriteProcessMemory_f923 {
  strings:
    $key_f923 = { ae 51 [2] 9c 73 [2] 9a 46 [2] b4 46 [2] 8b 5a }

  condition:
    any of them
}