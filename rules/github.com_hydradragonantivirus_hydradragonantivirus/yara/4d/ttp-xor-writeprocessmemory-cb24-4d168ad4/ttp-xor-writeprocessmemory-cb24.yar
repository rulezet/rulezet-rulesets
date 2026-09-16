rule TTP_XOR_WriteProcessMemory_cb24 {
  strings:
    $key_cb24 = { 9c 56 [2] ae 74 [2] a8 41 [2] 86 41 [2] b9 5d }

  condition:
    any of them
}