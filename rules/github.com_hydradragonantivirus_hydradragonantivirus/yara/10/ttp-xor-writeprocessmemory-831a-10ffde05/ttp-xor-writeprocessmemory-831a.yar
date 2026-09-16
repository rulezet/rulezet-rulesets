rule TTP_XOR_WriteProcessMemory_831a {
  strings:
    $key_831a = { d4 68 [2] e6 4a [2] e0 7f [2] ce 7f [2] f1 63 }

  condition:
    any of them
}