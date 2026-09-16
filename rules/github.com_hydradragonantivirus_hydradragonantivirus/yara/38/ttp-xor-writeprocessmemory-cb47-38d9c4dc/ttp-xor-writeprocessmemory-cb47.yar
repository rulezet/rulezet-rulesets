rule TTP_XOR_WriteProcessMemory_cb47 {
  strings:
    $key_cb47 = { 9c 35 [2] ae 17 [2] a8 22 [2] 86 22 [2] b9 3e }

  condition:
    any of them
}