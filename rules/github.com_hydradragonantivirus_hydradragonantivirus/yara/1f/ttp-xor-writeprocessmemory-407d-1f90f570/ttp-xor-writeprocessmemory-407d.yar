rule TTP_XOR_WriteProcessMemory_407d {
  strings:
    $key_407d = { 17 0f [2] 25 2d [2] 23 18 [2] 0d 18 [2] 32 04 }

  condition:
    any of them
}