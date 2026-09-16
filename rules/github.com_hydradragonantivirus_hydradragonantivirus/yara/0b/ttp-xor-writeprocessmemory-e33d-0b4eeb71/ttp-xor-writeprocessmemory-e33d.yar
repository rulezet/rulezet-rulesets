rule TTP_XOR_WriteProcessMemory_e33d {
  strings:
    $key_e33d = { b4 4f [2] 86 6d [2] 80 58 [2] ae 58 [2] 91 44 }

  condition:
    any of them
}