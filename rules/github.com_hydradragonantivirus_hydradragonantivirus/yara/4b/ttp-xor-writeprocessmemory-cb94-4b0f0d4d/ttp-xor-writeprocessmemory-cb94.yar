rule TTP_XOR_WriteProcessMemory_cb94 {
  strings:
    $key_cb94 = { 9c e6 [2] ae c4 [2] a8 f1 [2] 86 f1 [2] b9 ed }

  condition:
    any of them
}