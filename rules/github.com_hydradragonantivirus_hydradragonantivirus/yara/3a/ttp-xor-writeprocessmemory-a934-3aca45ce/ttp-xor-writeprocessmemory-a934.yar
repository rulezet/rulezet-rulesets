rule TTP_XOR_WriteProcessMemory_a934 {
  strings:
    $key_a934 = { fe 46 [2] cc 64 [2] ca 51 [2] e4 51 [2] db 4d }

  condition:
    any of them
}