rule TTP_XOR_WriteProcessMemory_cb6d {
  strings:
    $key_cb6d = { 9c 1f [2] ae 3d [2] a8 08 [2] 86 08 [2] b9 14 }

  condition:
    any of them
}