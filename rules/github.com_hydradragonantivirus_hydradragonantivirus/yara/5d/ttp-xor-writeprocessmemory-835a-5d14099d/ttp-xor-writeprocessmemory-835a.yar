rule TTP_XOR_WriteProcessMemory_835a {
  strings:
    $key_835a = { d4 28 [2] e6 0a [2] e0 3f [2] ce 3f [2] f1 23 }

  condition:
    any of them
}