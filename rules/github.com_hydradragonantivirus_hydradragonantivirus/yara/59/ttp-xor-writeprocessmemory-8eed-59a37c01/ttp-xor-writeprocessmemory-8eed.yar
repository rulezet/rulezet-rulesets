rule TTP_XOR_WriteProcessMemory_8eed {
  strings:
    $key_8eed = { d9 9f [2] eb bd [2] ed 88 [2] c3 88 [2] fc 94 }

  condition:
    any of them
}