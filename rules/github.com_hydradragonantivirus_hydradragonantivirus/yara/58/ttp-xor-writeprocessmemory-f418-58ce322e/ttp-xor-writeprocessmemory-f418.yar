rule TTP_XOR_WriteProcessMemory_f418 {
  strings:
    $key_f418 = { a3 6a [2] 91 48 [2] 97 7d [2] b9 7d [2] 86 61 }

  condition:
    any of them
}