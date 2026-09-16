rule TTP_XOR_WriteProcessMemory_822f {
  strings:
    $key_822f = { d5 5d [2] e7 7f [2] e1 4a [2] cf 4a [2] f0 56 }

  condition:
    any of them
}