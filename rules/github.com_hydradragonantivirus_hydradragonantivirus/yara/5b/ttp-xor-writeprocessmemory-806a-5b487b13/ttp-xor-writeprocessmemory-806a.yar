rule TTP_XOR_WriteProcessMemory_806a {
  strings:
    $key_806a = { d7 18 [2] e5 3a [2] e3 0f [2] cd 0f [2] f2 13 }

  condition:
    any of them
}