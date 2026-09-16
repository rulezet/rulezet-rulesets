rule TTP_XOR_WriteProcessMemory_8b8d {
  strings:
    $key_8b8d = { dc ff [2] ee dd [2] e8 e8 [2] c6 e8 [2] f9 f4 }

  condition:
    any of them
}