rule TTP_XOR_WriteProcessMemory_586e {
  strings:
    $key_586e = { 0f 1c [2] 3d 3e [2] 3b 0b [2] 15 0b [2] 2a 17 }

  condition:
    any of them
}