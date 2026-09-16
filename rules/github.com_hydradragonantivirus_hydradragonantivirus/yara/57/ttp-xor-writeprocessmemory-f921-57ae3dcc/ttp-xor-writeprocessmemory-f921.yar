rule TTP_XOR_WriteProcessMemory_f921 {
  strings:
    $key_f921 = { ae 53 [2] 9c 71 [2] 9a 44 [2] b4 44 [2] 8b 58 }

  condition:
    any of them
}