rule TTP_XOR_WriteProcessMemory_8501 {
  strings:
    $key_8501 = { d2 73 [2] e0 51 [2] e6 64 [2] c8 64 [2] f7 78 }

  condition:
    any of them
}