rule TTP_XOR_WriteProcessMemory_f901 {
  strings:
    $key_f901 = { ae 73 [2] 9c 51 [2] 9a 64 [2] b4 64 [2] 8b 78 }

  condition:
    any of them
}