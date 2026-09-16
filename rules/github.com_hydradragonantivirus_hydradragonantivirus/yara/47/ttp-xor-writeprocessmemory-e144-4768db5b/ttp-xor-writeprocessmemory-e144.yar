rule TTP_XOR_WriteProcessMemory_e144 {
  strings:
    $key_e144 = { b6 36 [2] 84 14 [2] 82 21 [2] ac 21 [2] 93 3d }

  condition:
    any of them
}