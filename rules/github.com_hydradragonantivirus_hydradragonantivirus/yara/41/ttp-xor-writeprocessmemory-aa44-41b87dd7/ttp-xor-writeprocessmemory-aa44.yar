rule TTP_XOR_WriteProcessMemory_aa44 {
  strings:
    $key_aa44 = { fd 36 [2] cf 14 [2] c9 21 [2] e7 21 [2] d8 3d }

  condition:
    any of them
}