rule TTP_XOR_WriteProcessMemory_951a {
  strings:
    $key_951a = { c2 68 [2] f0 4a [2] f6 7f [2] d8 7f [2] e7 63 }

  condition:
    any of them
}