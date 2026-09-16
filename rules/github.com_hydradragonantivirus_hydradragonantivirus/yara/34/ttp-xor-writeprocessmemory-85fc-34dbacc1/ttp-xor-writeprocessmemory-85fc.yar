rule TTP_XOR_WriteProcessMemory_85fc {
  strings:
    $key_85fc = { d2 8e [2] e0 ac [2] e6 99 [2] c8 99 [2] f7 85 }

  condition:
    any of them
}