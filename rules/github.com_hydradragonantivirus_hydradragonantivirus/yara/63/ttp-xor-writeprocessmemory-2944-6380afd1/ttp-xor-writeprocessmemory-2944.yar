rule TTP_XOR_WriteProcessMemory_2944 {
  strings:
    $key_2944 = { 7e 36 [2] 4c 14 [2] 4a 21 [2] 64 21 [2] 5b 3d }

  condition:
    any of them
}