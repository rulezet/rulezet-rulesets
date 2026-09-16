rule TTP_XOR_WriteProcessMemory_f924 {
  strings:
    $key_f924 = { ae 56 [2] 9c 74 [2] 9a 41 [2] b4 41 [2] 8b 5d }

  condition:
    any of them
}