rule TTP_XOR_WriteProcessMemory_f938 {
  strings:
    $key_f938 = { ae 4a [2] 9c 68 [2] 9a 5d [2] b4 5d [2] 8b 41 }

  condition:
    any of them
}