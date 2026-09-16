rule TTP_XOR_WriteProcessMemory_cb97 {
  strings:
    $key_cb97 = { 9c e5 [2] ae c7 [2] a8 f2 [2] 86 f2 [2] b9 ee }

  condition:
    any of them
}