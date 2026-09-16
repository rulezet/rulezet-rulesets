rule TTP_XOR_WriteProcessMemory_a944 {
  strings:
    $key_a944 = { fe 36 [2] cc 14 [2] ca 21 [2] e4 21 [2] db 3d }

  condition:
    any of them
}