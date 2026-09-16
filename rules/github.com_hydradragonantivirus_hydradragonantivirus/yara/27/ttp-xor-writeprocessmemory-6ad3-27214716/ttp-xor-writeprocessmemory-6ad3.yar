rule TTP_XOR_WriteProcessMemory_6ad3 {
  strings:
    $key_6ad3 = { 3d a1 [2] 0f 83 [2] 09 b6 [2] 27 b6 [2] 18 aa }

  condition:
    any of them
}