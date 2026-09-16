rule TTP_XOR_WriteProcessMemory_876a {
  strings:
    $key_876a = { d0 18 [2] e2 3a [2] e4 0f [2] ca 0f [2] f5 13 }

  condition:
    any of them
}