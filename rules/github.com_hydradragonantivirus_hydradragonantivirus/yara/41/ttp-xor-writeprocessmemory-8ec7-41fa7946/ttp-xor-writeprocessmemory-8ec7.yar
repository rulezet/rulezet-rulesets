rule TTP_XOR_WriteProcessMemory_8ec7 {
  strings:
    $key_8ec7 = { d9 b5 [2] eb 97 [2] ed a2 [2] c3 a2 [2] fc be }

  condition:
    any of them
}