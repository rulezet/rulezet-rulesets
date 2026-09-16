rule TTP_XOR_WriteProcessMemory_087d {
  strings:
    $key_087d = { 5f 0f [2] 6d 2d [2] 6b 18 [2] 45 18 [2] 7a 04 }

  condition:
    any of them
}