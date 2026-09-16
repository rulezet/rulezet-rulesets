rule TTP_XOR_WriteProcessMemory_145a {
  strings:
    $key_145a = { 43 28 [2] 71 0a [2] 77 3f [2] 59 3f [2] 66 23 }

  condition:
    any of them
}